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
        return {
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
                'wpa-ssid': cell.ssid,
                'wpa-username': username,
                'wpa-psk': passkey,
                'wireless-channel': 'auto',
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

    def __init__(self, interface, name, options=None):
        self.interface = interface
        self.name = name
        self.options = options or {}

    def __str__(self):
        """
        Returns the representation of a scheme that you would need
        in the /etc/network/interfaces file.
        """
        iface = "iface {interface}-{name} inet dhcp".format(**vars(self))
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
        return cls(interface, name, configuration(cell, passkey, username))

    def save(self):
        """
        Writes the configuration to the :attr:`interfaces` file.
        """
        assert not Scheme.find(self.interface, self.name)

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
