import re
import itertools

import wifi.subprocess_compat as subprocess
import wpactrl
from wifi.pbkdf2 import pbkdf2_hex


def configuration(cell, passkey=None, username=None):
    """
    Returns a dictionary of configuration options for cell

    Asks for a password if necessary
    """
    if not cell.encrypted:
        return
        {
            'wireless-essid': cell.ssid,
            'wireless-channel': 'auto',
        }
    else:
        if (cell.encryption_type == 'wpa2-?') or (cell.encryption_type == 'wpa2-psk'):
            if len(passkey) != 64:
                passkey = pbkdf2_hex(passkey, cell.ssid, 4096, 32)

            return {
                'wpa-ssid': cell.ssid,
                'wpa-psk': passkey,
                'wireless-channel': 'auto',
            }
        elif (cell.encryption_type == 'wpa2-eap'):
            return {
                'ssid': '"'+cell.ssid+'"',
                'key_mgmt': 'WPA-EAP',
                'scan_ssid': '1',
                'proto': 'RSN',
                'pairwise': 'CCMP TKIP',
                'group': 'CCMP TKIP',
                'eap': 'PEAP',
                'phase1': '"peapver=0"'
                'phase2': '"MSCHAPV2"'
                'identity': '"'+username+'"',
                'password': '"'+passkey+'"',
            }
        else:
            raise NotImplementedError


class Scheme(object):
    """
    Saved configuration for connecting to a wireless network.  This
    class provides a Python interface to the /etc/network/interfaces
    file.
    """

    interfaces = '/etc/network/interfaces'

    def __init__(self, interface, name, options=None,encryption_type=None):
        self.interface = interface
        self.name = name
        self.options = options or {}
        self.encryption_type = encryption_type

    def __str__(self):
        """
        Returns the representation of a scheme that you would need
        in the /etc/network/interfaces file.
        """
        if self.encryption_type == 'wpa2-eap':
            iface = "auto {interface}\n".format(**vars(self))
            iface += "iface {interface} inet dhcp\n".format(**vars(self))
            iface += ''.join("\t pre-up wpa_supplicant -Bw -Dwext -i {interface} -c/etc/wpa_supplicant_enterprise.conf\n")
            iface += ''.join("\t post-down killall -q wpa_supplicant")
            return iface
        else:
            iface = "iface {interface} inet dhcp".format(**vars(self))
            options = ''.join("\n    {k} {v}".format(k=k, v=v) for k, v in self.options.items())
            return iface + options + '\n'

    def __repr__(self):
        return 'Scheme(interface={interface!r}, name={name!r}, options={options!r}'.format(**vars(self))

    @classmethod
    def all(cls):
        """
        Returns an generator of saved schemes.
        """
        with open(cls.interfaces, 'r') as f:
            return extract_schemes(f.read())

    @classmethod
    def where(cls, fn):
        return list(filter(fn, cls.all()))

    @classmethod
    def find(cls, interface, name):
        """
        Returns a :class:`Scheme` or `None` based on interface and
        name.
        """
        try:
            return cls.where(lambda s: s.interface == interface and s.name == name)[0]
        except IndexError:
            return None

    @classmethod
    def for_cell(cls, interface, name, cell, passkey=None, username=None):
        """
        Intuits the configuration needed for a specific
        :class:`Cell` and creates a :class:`Scheme` for it.
        """
        if cell.encrypted:
            return cls(interface, name, configuration(cell, passkey, username), cell.encryption_type)
        else:
            return cls(interface, name, configuration(cell, passkey, username))


    def save(self):
        """
        Writes the configuration to the :attr:`interfaces` file.
        If WPA-EAP network, also write to /etc/wpa_supplicant_enterprise.conf
        """
        assert not Scheme.find(self.interface, self.name)
        
        #Adapted from Ubuntu 802.1x Authentication page: https://help.ubuntu.com/community/Network802.1xAuthentication
        if self.encryption_type == 'wpa2-eap':
            configuration_file = '/etc/wpa_supplicant_enterprise.conf'
            with open(configuration_file, 'a') as config_file:
                config_file.write('ctrl_interface=/var/run/wpa_supplicant_enterprise\n')
                config_file.write('ctrl_interface)group=0\n')
                config_file.write('eapol_version=2\n')
                config_file.write('ap_scan=0\n')
                options = ''.join("\n{k}={v}".format(k=k, v=v) for k, v in test_dic.items())
                config_file.write(options[1:])
        else:
            with open(self.interfaces, 'a') as f:
                f.write('\n')
                f.write(str(self))

    @property
    def iface(self):
        return '{0}-{1}'.format(self.interface, self.name)

    def as_args(self):
        args = list(itertools.chain.from_iterable(
            ('-o', '{k}={v}'.format(k=k, v=v)) for k, v in self.options.items()))

        return [self.interface + '=' + self.iface] + args

    def activate(self):
        """
        Connects to the network as configured in this scheme.
        """
        if self.encryption_type == 'wpa2-eap':
            response = subprocess.check_output(['wpa_supplicant', '-B', '-i', self.interface, '-Dwext', '-c', '/etc/wpa_supplicant_enterprise.conf'])
            if ("Authentication succeeded" in response) or ("EAP authentication completed successfully" in response):
                print 'Wi-Fi Connection established!'
            else:
                print 'Could not connect to Wi-Fi network!'
        else:
            subprocess.check_call(['/sbin/ifdown', self.interface])
            subprocess.check_call(['/sbin/ifup'] + self.as_args())


# TODO: support other interfaces
scheme_re = re.compile(r'iface\s+(?P<interface>wlan\d?)(?:-(?P<name>\w+))?')


def extract_schemes(interfaces):
    lines = interfaces.splitlines()
    while lines:
        line = lines.pop(0)

        if line.startswith('#') or not line:
            continue

        match = scheme_re.match(line)
        if match:
            options = {}
            interface, scheme = match.groups()

            if not scheme or not interface:
                continue

            while lines and lines[0].startswith(' '):
                key, value = re.sub(r'\s{2,}', ' ', lines.pop(0).strip()).split(' ', 1)
                options[key] = value

            scheme = Scheme(interface, scheme, options)

            yield scheme
