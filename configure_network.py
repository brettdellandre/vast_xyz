#!/usr/bin/env python3

import re
import os
import sys
import datetime
import logging
import argparse
import ipaddress
import subprocess
import json
import shutil
import pwd
from enum import Enum, auto
from time import sleep
from math import ceil
from logging.handlers import RotatingFileHandler
from collections import namedtuple


class InterfaceVendor(Enum):
    NONE = 0
    Mellanox = 0x15b3
    Intel = 0x8086
    QLogic = 4215 # AMD servers


INTERFACE_SYSFS = '/sys/class/net/'
DEFAULT_IB_BOND_MTU = dict(connected=65520, datagram=2044)
CONNECTED_MODE = dict(connected='yes', datagram='no')
REBOOT_FLAG_FILE = '/run/configure_network_requires_reboot'
SSHD_CONFIG = '/etc/ssh/sshd_config'
UDEV_IB_RULES_FILE = '/usr/lib/udev/rules.d/70-persistent-ipoib.rules'
CFG_FILE = '/etc/vast-configure_network.py-params.ini'
SHA1_FILE = '/etc/vast-configure-network-sha1'
RESOLV_CONF_FILE = '/etc/resolv.conf'
MLX_POST_OPENIBD_CONFIGURE_FILE = '/usr/bin/configure_mlx_post_openibd.sh'

LOCALHOST_IP = '127.0.0.1'
TECHNICIAN_IP = '192.168.2.2'

''' S2600KPR and S2600BPB are cnode made by Intel,  NSS2560 is dnode made by Sanmina'''
B2B_ALLOWED_CNODE_PRODUCT_NAME = ['S2600KPR','S2600BPB']
B2B_ALLOWED_DNODE_PRODUCT_NAME = ['NSS2560']
B2B_TEMPLATE = '192.168.2.{node}'
B2B_IPMI_IP_NETMASK = '255.255.255.0'
B2B_ALLOWED_INTERFACES = ['eno1','ens6']

ARGLESS_RUN_PARAM = '--load-params-from-file'
ONLY_GENERATE_CONF_FILES = '--only-generate-conf-files'

CONNECTX6_FW = [20, 28, 4000]

LOG_DIR = '/vast/log/configure_network'

IP_REGEX = re.compile(r'\d+: (?P<iface>[\w\.]+) +(?P<ver>inet(?:6|)) (?P<ip>\w+::\w+:\w+:\w+:\w+/\d+|\d+\.\d+\.\d+\.\d+/\d+) [\w\. ]* (?P<label>[\w\.]+:\w+|).*')
IfAddr = namedtuple('IfAddr', ['ver', 'ip', 'subnet_mask', 'label'])


class MSTDevice:
    def __init__(self, device_type, mst, pci, rdma, net, numa):
        self.device_type = device_type
        self.mst = mst
        self.pci = pci
        self.rdma = rdma
        self.net = net
        self.numa = numa

    def __str__(self):
        return f'{self.device_type}: {self.mst} pci={self.pci} rdma={self.rdma} net={self.net} numa={self.numa}'

    @property
    def net_iface(self):
        return self.net.split('-')[-1]

class HWLocation(Enum):
    LEFT = auto()
    RIGHT = auto()
    SINGLE = auto()
    NA = auto()

def get_interfaces():
    '''returns a mapping between a name of an interface (e.g. eth3) to an InterfaceVendor (enum value)'''
    result = []
    for interface in os.listdir(INTERFACE_SYSFS):
        device_path = os.path.join(INTERFACE_SYSFS, interface, 'device')
        if not os.path.exists(device_path):
            vendor = 0
        else:
            vendor_path = os.path.join(device_path, 'vendor')
            with open(vendor_path) as vendor_file:
                vendor = int(vendor_file.read(), 16)  # the content is a hex string 0x1234
        try:
            result.append(Interface(name=interface,
                                    vendor=InterfaceVendor._value2member_map_[vendor],
                                    mac=get_mac(interface),
                                    is_virtual=is_virtual(interface)))
        except KeyError:
            raise ValueError('Unknown vendor {} for interface {}'.format(
                vendor, interface))

    return sorted(result, key=lambda i: i.name)


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
log_fmt = '%(asctime)s (P%(process)d) {%(levelname)s} [configure_network:%(filename)s:%(lineno)d] %(message)s'
log_formatter = logging.Formatter(log_fmt)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.DEBUG)
logger.addHandler(stream_handler)


USAGE = '''
supported modes:
    ETH only cluster:
        "management" - bond0 (alias "m")
        "vast internal ips" - ETH VLAN interfaces

    IB only cluster:
        "management" - bond0 (alias "m")
        "vast internal ips" - IB physical interfaces

Example:
configure_network.py NODE --ext-interface EXT_IF --ext-ip EXT_IP --ext-gateway EXT_GATEWAY --ext-dns EXT_DNS --ext-netmask EXT_DNS --hostname HOSTNAME --mgmt-vip MGMT_VIP

"external ip" can be configured on "management" interface by omitting "--ext-interface" argument:
configure_network.py NODE --ext-ip EXT_IP --ext-gateway EXT_GATEWAY --ext-dns EXT_DNS --ext-netmask EXT_DNS --hostname HOSTNAME --mgmt-vip MGMT_VIP
'''

class InterfaceTemplates(Enum):
    ETH_NO_IP = 'ETH_NO_IP'
    ETH_SLAVE = 'ETH_SLAVE'
    ETH_BOND = 'ETH_BOND'
    ETH_VLAN = 'ETH_VLAN'
    ETH_BOND_VLAN = 'ETH_BOND_VLAN'
    IB_PHYS = 'IB_PHYS'
    IB_SLAVE = 'IB_SLAVE'
    IB_BOND = 'IB_BOND'
    DISABLED_INTERFACE_TEMPLATE = 'DISABLED_INTERFACE_TEMPLATE'
    EXTERNAL = 'EXTERNAL'
    EXTERNAL_ALIAS = 'EXTERNAL_ALIAS'
    ALIAS = 'ALIAS'
    TECHNICIAN = 'TECHNICIAN'


interface_templates = {
    InterfaceTemplates.ETH_NO_IP: '''DEVICE={interface}
TYPE=Ethernet
BOOTPROTO=none
ONBOOT=yes
MTU={eth_mtu}
''',
    InterfaceTemplates.ETH_SLAVE: '''DEVICE={interface}
NAME={interface}
TYPE=Ethernet
BOOTPROTO=none
ONBOOT=yes
MASTER={bond_master}
SLAVE=yes
'''.lstrip(),
    InterfaceTemplates.ETH_BOND: '''DEVICE={interface}
NAME={interface}
TYPE=Bond
BONDING_MASTER=yes
ONBOOT=yes
BOOTPROTO=none
BONDING_OPTS="mode=active-backup miimon=100 xmit_hash_policy=layer2+3"
MTU={eth_mtu}
IPADDR=
NETMASK=
GATEWAY=
DNS1={ext_bond_dns[0]}
DNS2={ext_bond_dns[1]}
PEERDNS=yes
'''.lstrip(),

    InterfaceTemplates.ETH_VLAN: '''DNS1=
DNS2=
PEERDNS=yes
BOOTPROTO=static
DEVICE={interface}
HWADDR={mac}
ONBOOT=yes
VLAN=yes
MTU={eth_mtu}
'''.lstrip(),

    InterfaceTemplates.ETH_BOND_VLAN: '''BOOTPROTO=static
DEVICE={interface}
NAME={interface}
ONPARENT=yes
VLAN=yes
PEERDNS=yes
'''.lstrip(),

    InterfaceTemplates.IB_PHYS: '''TYPE=Infiniband
DNS1={ext_dns[0]}
DNS2={ext_dns[1]}
PEERDNS=yes
BOOTPROTO=static
DEVICE={interface}
ONBOOT=yes
VLAN=no
CONNECTED_MODE={connected_mode}
MTU={ib_mtu}
'''.lstrip(),

    InterfaceTemplates.IB_SLAVE: '''DEVICE={interface}
NAME={interface}
BOOTPROTO=none
ONBOOT=yes
TYPE=Infiniband
MASTER=bond0
CONNECTED_MODE={connected_mode}
SLAVE=yes
'''.lstrip(),

    InterfaceTemplates.IB_BOND: '''DEVICE={interface}
NAME={interface}
TYPE=Bond
BONDING_MASTER=yes
ONBOOT=yes
BOOTPROTO=none
BONDING_OPTS="mode=active-backup miimon=100 updelay=0 downdelay=0"
MTU={ib_mtu}
DNS1={ext_dns[0]}
DNS2={ext_dns[1]}
PEERDNS=yes
'''.lstrip(),

    InterfaceTemplates.DISABLED_INTERFACE_TEMPLATE: '''DEVICE={interface}
NAME={interface}
BOOTPROTO=none
ONBOOT=no
'''.lstrip(),

    InterfaceTemplates.EXTERNAL: '''TYPE=Ethernet
DNS1={ext_dns[0]}
DNS2={ext_dns[1]}
PEERDNS=yes
BOOTPROTO=static
DEVICE={ext_interface}
HWADDR={mac}
ONBOOT=yes
VLAN=no
'''.lstrip(),

    InterfaceTemplates.EXTERNAL_ALIAS: '''IPADDR={ext_ip}
NETMASK={ext_netmask}
GATEWAY={ext_gateway}
DEVICE={interface}
ONPARENT=yes
'''.lstrip(),

    InterfaceTemplates.ALIAS: '''IPADDR={ip}
NETMASK={data_netmask}
GATEWAY=
DEVICE={interface}
ONPARENT=yes
'''.lstrip(),

    InterfaceTemplates.TECHNICIAN: '''DEVICE={interface}
NAME={interface}
BOOTPROTO=none
ONBOOT=yes
IPADDR={ip}
NETMASK=255.255.255.0
'''
}


IB_UDEV_RULE= '''SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{{address}}=="*:{mac}", NAME="{interface}"
'''

INTERFACE_CONFIG_DIR = '/etc/sysconfig/network-scripts'
INTERFACE_CONFIG_FILE_TEMPLATE = INTERFACE_CONFIG_DIR + '/ifcfg-{}'
VMAN_DIR = '/vast/vman'
MGMT_VIP_FILE = '/vast/vman/mgmt-vip'
MGMT_INNER_VIP_FILE = '/vast/vman/mgmt-inner-vip'
DOCKER_DAEMON_CONFIG_FILE = '/etc/docker/daemon.json'
LOCAL_DOCKER_REGISTRY_NAME = 'vastdata.registry.local'
LOCAL_DOCKER_REGISTRY_ENTRY = f'{LOCAL_DOCKER_REGISTRY_NAME}:5000'
DOCKER_INSECURE_REGISTRY_KEY = 'insecure-registries'
DOCKER_DEFAULT_BRIDGE_IP = '172.17.0.1'
DOCKER_DEFAULT_BRIDGE_IP_SUBNET_BITS = 16
DEFAULT_IP_SUBNET_BITS = 24
INTERFACE_SUBNETS_FILE = '/etc/vast-configure_network-subnets'


class IfcfgScriptFile:
    def __init__(self, device=None, type=None, bootproto=None, onboot=None, mtu=None, name=None,
                 bonding_master=None, bonding_opts=None, ipaddr=None, netmask=None, gateway=None,
                 dns1=None, dns2=None, peerdns=None, hwaddr=None, vlan=None, network=None,
                 broadcast=None, onparent=None, master=None, slave=None, connected_mode=None, ipv6addr=None,
                 *args, **kwargs):
        self.device = device
        self.type = type
        self.bootproto = bootproto
        self.onboot = onboot
        self.mtu = mtu
        self.name = name
        self.bonding_master = bonding_master
        self.bonding_opts = bonding_opts
        self.ipaddr = ipaddr
        self.netmask = netmask
        self.gateway = gateway
        self.dns1 = dns1
        self.dns2 = dns2
        self.peerdns = peerdns
        self.hwaddr = hwaddr
        self.vlan = vlan
        self.network = network
        self.broadcast = broadcast
        self.onparent = onparent
        self.master = master
        self.slave = slave
        self.ipv6addr = ipv6addr

    def __repr__(self):
        return '{}(device={})'.format(self.__class__.__name__, self.device)

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def parse_ifcfg_file(ifcfg_file_path):
        parsed_attrs = {}

        with open(ifcfg_file_path, 'r') as f:
            for line in f:
                if line.startswith('#') or '=' not in line:
                    continue

                k, v = line.split('=', 1)
                k = k.strip().lower()
                v = v.strip()
                v = int(v) if v.isdigit() else v
                parsed_attrs[k] = v

        return parsed_attrs

    @classmethod
    def read(cls, ifcfg_file_path):
        parsed_attrs = cls.parse_ifcfg_file(ifcfg_file_path)
        return cls(**parsed_attrs)

    def update_from_ifcfg_file(self, ifcfg_file_path):
        parsed_attrs = self.parse_ifcfg_file(ifcfg_file_path)

        for k, v in parsed_attrs.items():
            setattr(self, k, v)

    def as_dict(self):
        return vars(self)

    @property
    def is_ib(self):
        return self.type == 'Infiniband'

    @property
    def is_eth(self):
        return self.type == 'Ethernet'

    @property
    def is_bond(self):
        return self.type == 'Bond'


class Interface(object):
    def __init__(self, name, vendor=InterfaceVendor.NONE, mac='', is_virtual=False):
        self.name = name
        self.vendor = vendor
        self.is_virtual = is_virtual
        self.is_ib = name.startswith('ib')
        self.mac = mac

    def __repr__(self):
        return 'Interface(name={!r}, mac={!r}, vendor={!r}, is_virtual={})'.format(self.name, self.mac, self.vendor, self.is_virtual)


def get_script_sha1():
    if not os.path.exists(SHA1_FILE):
        return 'unknown'
    with open(SHA1_FILE, 'r') as f:
        return f.read().strip()


def get_netmask_bits_position(netmask):
    octet3 = int(netmask.split(".")[2])
    for i in range(7):
        if (255 << i & 255) == octet3:
            return i

    assert False, f'netmask={netmask} is not a valid netmask'


def update_etc_hosts(hosts_records, etc_hosts_file='/etc/hosts'):
    new_etc_hosts = ''
    added = []

    def _get_record(e):
        added.append(e)
        return '{} {}\n'.format(hosts_records[e], e)

    with open(etc_hosts_file, 'r') as etc_hosts_fh:
        etc_hosts = etc_hosts_fh.readlines()
    for line in etc_hosts:
        try:
            i, e = line.strip().split(maxsplit=1)
            if e in hosts_records:
                new_etc_hosts += _get_record(e)
            else:
                new_etc_hosts += line
        except:
            new_etc_hosts += line
    if len(added) != len(hosts_records):
        new_etc_hosts += '\n#records added automaticlly by configure_network.py script\n'
        for e in hosts_records:
            if e not in added:
                new_etc_hosts += _get_record(e)
    with open(etc_hosts_file, 'w') as etc_hosts_fh:
        etc_hosts_fh.write(new_etc_hosts)


def prepare_dockerd_configs(args):
    configs = {}
    changed = False

    if os.path.exists(DOCKER_DAEMON_CONFIG_FILE) and os.path.getsize(DOCKER_DAEMON_CONFIG_FILE) > 0:
        logger.info(f'reading existing docker daemon configs: {DOCKER_DAEMON_CONFIG_FILE}')
        with open(DOCKER_DAEMON_CONFIG_FILE, 'r') as f:
            configs = json.load(f)
    else:
        os.makedirs(os.path.dirname(DOCKER_DAEMON_CONFIG_FILE), exist_ok=True)

    insecure_registries = configs.setdefault(DOCKER_INSECURE_REGISTRY_KEY, [])

    if LOCAL_DOCKER_REGISTRY_ENTRY not in insecure_registries:
        insecure_registries.append(LOCAL_DOCKER_REGISTRY_ENTRY)
        changed = True

    if args.dockerd_bip is not None:
        configs['bip'] = format_dockerd_bip_address(args.dockerd_bip)
        changed = True

    return changed, configs


def update_docker_configs(args):
    changed, configs = prepare_dockerd_configs(args)

    if changed:
        with open(DOCKER_DAEMON_CONFIG_FILE, 'w') as f:
            json.dump(configs, f)

        logger.info(f'docker daemon configs updated')

    return changed


def update_sshd_config(*listen_ips, erase_existing = True):
    with open(SSHD_CONFIG, 'r') as sshd_config_fh:
        sshd_lines = sshd_config_fh.readlines()

    listen_line_num = 0
    for i, line in enumerate(sshd_lines):
        if "ListenAddress" in line:
            if listen_line_num  == 0:
                listen_line_num = i
            if erase_existing and not "#ListenAddress" in line:
                sshd_lines[i] = f'#{line}'

    for ip in listen_ips:
        line = f'ListenAddress {ip}\n'
        if line not in sshd_lines:
            sshd_lines.insert(listen_line_num, line)

    with open(SSHD_CONFIG, 'w') as sshd_config_fh:
        sshd_config_fh.writelines(sshd_lines)


def backup_file(dirname, filename):
    backup = os.path.join(dirname, 'bk.' + filename)
    logger.info('backing up {} to {}'.format(dirname, filename))
    os.rename(os.path.join(dirname, filename), backup)


def get_mac(interface):
    if os.path.exists(os.path.join(INTERFACE_SYSFS, interface, 'bonding_slave')):
        with open(os.path.join(INTERFACE_SYSFS, interface, 'bonding_slave/perm_hwaddr')) as f:
            return f.read().strip()

    if os.path.exists(os.path.join(INTERFACE_SYSFS, interface, 'address')):
        with open(os.path.join(INTERFACE_SYSFS, interface, 'address')) as f:
            return f.read().strip()


def is_virtual(interface):
    return os.path.exists(
        os.path.join(INTERFACE_SYSFS, interface, 'device', 'physfn'))


def filter_ifs(interfaces, **params):
    res = []
    for interface in interfaces:
        for k, v in params.items():
            if getattr(interface, k) != v:
                break
        else:
            res.append(interface)
    return res

def interfaces_from_arg(interfaces, arg):
    names = arg.split(',') if arg else []
    ifs = list(filter(lambda i: i.name in names, interfaces))
    assert sorted(names) == sorted([i.name for i in ifs])
    return ifs

def interfaces_to_arg(interfaces):
    return ','.join([i.name for i in interfaces])

def configure_hostname(name):
    logger.info('setting hostname to: {}'.format(name))
    assert os.system('hostnamectl set-hostname {}'.format(name)) == 0


def get_mgmt_vip_from_file():
    with open(MGMT_VIP_FILE) as f:
        return f.read().strip()


def get_interfaces_from_args(args, external_interfaces=True, internal_virtual_interfaces=True,
                             internal_interfaces=True):
    interfaces = set()

    for param, arg in [
        [external_interfaces, 'external_interfaces'],
        [internal_virtual_interfaces, 'internal_virtual_interfaces'],
        [internal_interfaces, 'internal_interfaces']
    ]:
        arg_value = getattr(args, arg, None)

        if param and arg_value is not None:
            interfaces.update([iface.strip() for iface in arg_value.split(',')])

    return list(interfaces)


def get_configured_mtus(interfaces_list):
    iface_path_to_mtu = {}

    for script in filter(lambda x: x.startswith('ifcfg') and any(iface in x for iface in interfaces_list),
                         os.listdir(INTERFACE_CONFIG_DIR)):
        script_path = '{}/{}'.format(INTERFACE_CONFIG_DIR, script)
        script_obj = IfcfgScriptFile.read(script_path)

        if script_obj.mtu is None or script_obj.is_bond:
            continue

        logger.info(f'found iface={script} with configured mtu={script_obj.mtu}')
        iface_path_to_mtu[script_path] = script_obj.mtu

    return iface_path_to_mtu


def write_kv_to_ifcfg(ifcfg_path, k, v):
    logger.info(f'{ifcfg_path} writing {k}={v}')

    file_lines = []
    with open(ifcfg_path, 'r') as f:
        file_lines = f.readlines()

    write_line = f'{k}={v}\n'
    k_found = False
    new_file_lines = []
    for line in file_lines:
        if '=' not in line:
            new_file_lines.append(line)
            continue

        line_k, *_ = line.split('=')
        if k != line_k:
            new_file_lines.append(line)
            continue

        assert not k_found, f'found more than 1 instance of key={k} in in {ifcfg_path}'
        k_found = True
        new_file_lines.append(write_line)

    if not k_found:
        new_file_lines.append(write_line)

    with open(ifcfg_path, 'w') as f:
        file_lines = f.writelines(new_file_lines)


def _exit(message):
    logger.error(message)
    sys.exit(1)


def configure_ipmi(ipmi_ip, ipmi_netmask, ipmi_default_gateway):
    logger.info('configuring ipmi with ip={}, netmask={}, default gateway={}'.format(ipmi_ip, ipmi_netmask, ipmi_default_gateway))
    assert os.system('sudo ipmitool lan set 1 ipsrc static') == 0
    sleep(2)
    # sometimes ipmi failes to set the address and it become unavailable if the address is the same
    assert os.system('sudo ipmitool lan set 1 ipaddr 0.0.0.0') == 0
    sleep(2)
    assert os.system('sudo ipmitool lan set 1 ipaddr {}'.format(ipmi_ip)) == 0
    sleep(2)
    assert os.system('sudo ipmitool lan set 1 netmask {}'.format(ipmi_netmask)) == 0
    sleep(2)
    assert os.system('sudo ipmitool lan set 1 defgw ipaddr {}'.format(ipmi_default_gateway)) == 0


def get_ifaces_addrs():
    cmd = ['/usr/sbin/ip', '-o', 'a']
    output = subprocess.run(cmd, check=True, encoding='ascii', stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    addrs = {}

    for line in output.splitlines():
        line = line.strip()
        match = IP_REGEX.search(line)

        if not match:
            continue
        addr_info = match.groupdict()
        ip, subnet_mask = addr_info['ip'].split('/')
        label = addr_info['label'].split(':')[-1]
        addr = IfAddr(ver=addr_info['ver'], ip=ip, subnet_mask=subnet_mask, label=label)
        addrs.setdefault(addr_info['iface'], []).append(addr)

    return addrs

def extract_mlx_interface(interface):
    """
    expected output of 'ibdev2netdev' is in the form of:
    mlx5_0 port 1 ==> enp94s0f0 (Up)
    mlx5_1 port 1 ==> enp94s0f1 (Up)
    mlx5_2 port 1 ==> enp94s0f2 (Up)
    mlx5_3 port 1 ==> enp94s0f3 (Up)
    """
    cmd = ['ibdev2netdev']
    output = subprocess.run(cmd, check=True, encoding='ascii', stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    for line in output.splitlines():
        if line.split(' ')[-2] == interface:
            return line.split(' ')[0]

    assert False, 'could not find mlx interface for: %s' % interface

def get_host_configured_internal_ifaces(args):
    configured_addrs = get_ifaces_addrs()
    data_ip1, data_ip2, _ = get_internal_ips(args)
    data_ips = {data_ip1, data_ip2}
    internal_ifaces = []

    if args.fresh_install:
        return []

    for iface, addrs in configured_addrs.items():
        for addr in addrs:
            if addr.ip not in data_ips:
                continue
            internal_ifaces.append(iface)

    assert len(internal_ifaces) in [2, 0], f'invalid num of internal_ifaces={internal_ifaces}'
    internal_ifaces.sort()
    return internal_ifaces


def do_start_mst():
    subprocess.run(['mst', 'start'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def get_mst_devices(start_mst=True):
    """
    expected output of `mst status -v` is in the form of:
    MST modules:
    ------------
        MST PCI module is not loaded
        MST PCI configuration module loaded
    PCI devices:
    ------------
    DEVICE_TYPE             MST                           PCI       RDMA            NET                       NUMA
    ConnectX6(rev:0)        /dev/mst/mt4123_pciconf0.1    3b:00.1   mlx5_1          net-enp59s0f1             0

    ConnectX6(rev:0)        /dev/mst/mt4123_pciconf0      3b:00.0   mlx5_0          net-enp59s0f0             0

    ConnectX5(rev:0)        /dev/mst/mt4119_pciconf0.1    5e:00.1   mlx5_3          net-enp94s0f1             0

    ConnectX5(rev:0)        /dev/mst/mt4119_pciconf0      5e:00.0   mlx5_2          net-enp94s0f0             0
    """
    if start_mst:
        do_start_mst()
    devices = []
    output = subprocess.run(['mst', 'status', '-v'], check=True, encoding='ascii',
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    lines = output.splitlines()

    for line in lines:
        line = line.strip()
        if not line.startswith('ConnectX'):
            continue
        logger.info(f'mst device: {line}')
        params = [e.strip() for e in line.split()]
        assert len(params) == 6
        devices.append(MSTDevice(*params))

    return devices


def get_mst_device_for_mst(mst, mst_devices):
    for device in mst_devices:
        if mst == device.mst:
            return device
    return None


def get_port_type_for_mst_device(mst_device, internal_ifaces):
    return 'internal' if mst_device.net_iface in internal_ifaces else 'external'


def get_mlx_configs(start_mst=True):
    # we first start mst so devices will be identified by their mst device path for consistency
    if start_mst:
        do_start_mst()
    subprocess.run(['mst', 'start'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fw_configs = []
    output = subprocess.check_output(['mlxconfig', 'query']).decode('ascii')
    for device_config in re.split('\s*Device #\d*:', output):
        config = dict()
        for param_str in device_config.splitlines():
            param_pair = re.findall('(.*):\s+(.*)' if ':' in param_str else '([^\s]*)\s+(.*)', param_str.strip())
            config.update(param_pair)
        if config:
            fw_configs.append(config)
    return fw_configs


def configure_fw(args):
    '''port mode: 'eth' or 'ib' or None to leave as is'''
    should_reboot = False
    internal_ifaces = get_host_configured_internal_ifaces(args)
    if not internal_ifaces:
        logger.info('could not find configured internal interfaces')
        internal_ifaces = get_interfaces_from_args(args, external_interfaces=False,
                                                   internal_virtual_interfaces=False, internal_interfaces=True)
    internal_ifaces = [iface.split('.', 1)[0] for iface in internal_ifaces]  # we are looking for the parent ifaces
    logger.info(f'using internal_ifaces={internal_ifaces}')

    do_start_mst()
    fw_configs = get_mlx_configs(start_mst=False)
    num_nics = len(fw_configs)
    mst_devices = get_mst_devices(start_mst=False)
    configs_list = []

    if args.port_mode is None:
        if num_nics == 1:
            for port_type in ['external', 'internal']:
                configs_list.append((fw_configs[0], port_type, None))
        else:
            assert internal_ifaces, f'internal interfaces are missing from host or args'

            for fw_config in fw_configs:
                mst_dev = get_mst_device_for_mst(fw_config['Device'], mst_devices)
                port_type = get_port_type_for_mst_device(mst_dev, internal_ifaces)
                configs_list.append((fw_config, port_type, None))
    elif '=' not in args.port_mode:
        # legacy port_mode format
        if num_nics == 1:
            args.port_mode = f'external={args.port_mode},internal={args.port_mode}'
            for port_type, port_mode in (type_mode.split('=') for type_mode in args.port_mode.split(',')):
                configs_list.append((fw_configs[0], port_type, port_mode))
        else:
            if not internal_ifaces:
                internal_ifaces = [mst_dev.net_iface for mst_dev in mst_devices]
                logger.info(f'using internal_ifaces={internal_ifaces}')
                assert len(internal_ifaces) == 2

            int_port_mode = 'ib' if all('ib' in iface for iface in internal_ifaces) else 'eth'
            args.port_mode = f'external={args.port_mode},internal={int_port_mode}'
            port_type2port_mode = dict(type_mode.split('=') for type_mode in args.port_mode.split(','))

            for fw_config in fw_configs:
                mst_dev = get_mst_device_for_mst(fw_config['Device'], mst_devices)
                port_type = get_port_type_for_mst_device(mst_dev, internal_ifaces)
                port_mode = port_type2port_mode[port_type]
                configs_list.append((fw_config, port_type, port_mode))
    else:
        # full port_mode format - external=(eth|ib),interanl=(eth|ib)
        assert internal_ifaces, f'internal interfaces are missing from host or args'

        port_type2port_mode = dict(type_mode.split('=') for type_mode in args.port_mode.split(','))

        for fw_config in fw_configs:
            mst_dev = get_mst_device_for_mst(fw_config['Device'], mst_devices)
            port_type = get_port_type_for_mst_device(mst_dev, internal_ifaces)
            port_mode = port_type2port_mode[port_type]
            configs_list.append((fw_config, port_type, port_mode))

    for params, port_type, port_mode in configs_list:
        device = params['Device']
        is_internal = port_type == 'internal'

        assert port_mode in ['ib', 'eth', None], "invalid value: --port-mode"
        assert port_type in ['internal', 'external'], "invalid value: --port-mode"

        logger.info(f"device={device}: port_type={port_type} port_mode={port_mode} "
                    f"NUM_OF_VFS={params['NUM_OF_VFS']} SRIOV_EN={params['SRIOV_EN']}")

        # ensure we have VFs only on internal NIC (in single NIC setup it's both internal and external)
        if (
            (is_internal and not (params['NUM_OF_VFS'] == '1' and params['SRIOV_EN'].startswith('True'))) or
            (not is_internal and num_nics > 1 and not (params['NUM_OF_VFS'] == '0' and params['SRIOV_EN'].startswith('False')))
        ):
            args = ['mlxconfig', '-y', '-d', device, 'set', f'SRIOV_EN={int(is_internal)}', f'NUM_OF_VFS={int(is_internal)}']
            subprocess.check_output(args)
            logger.info(f'device {device}: updated firmware parameters {args}')
            should_reboot = True

        try:
            p1_eth = params['LINK_TYPE_P1'].startswith('ETH')
            p2_exists = 'LINK_TYPE_P2' in params
            p2_eth = params['LINK_TYPE_P2'].startswith('ETH') if p2_exists else False
            if p1_eth != p2_eth and port_mode is None and p2_exists:
                _exit('ports are in mixed mode (ETH and IB). please specify --port-mode explicitly.')
            if port_mode is not None:
                eth_required = port_mode.lower() == 'eth'
                mode = '2' if eth_required else '1'
                if not p1_eth == eth_required or (not p2_eth == eth_required and p2_exists):
                    args = ['mlxconfig', '-y', '-d', device, 'set']
                    if p1_eth != eth_required:
                        args.append('LINK_TYPE_P1=' + mode)
                    if p2_eth != eth_required and p2_exists:
                        args.append('LINK_TYPE_P2=' + mode)
                    subprocess.check_output(args).decode('ascii')
                    logger.info(f'device {device}: updated firmware parameters {args}')
                    should_reboot = True
        except KeyError:
            pass

    if should_reboot:
        with open(REBOOT_FLAG_FILE, "w") as f:
            pass
        _exit('FW parameters have changed. please reboot and rerun!')

    if os.path.exists(REBOOT_FLAG_FILE):
        _exit('FW parameters have changed before without reboot. Please reboot and rerun!')


def create_args_parser(update_params=None, optional_only=False):

    #first we parse "only" usage of --mgmt-vip
    try:
        #supress stdout + stderr since faliure reason is not important#
        _stdout = sys.stdout
        sys.stdout = open('/dev/null', 'w')
        _stderr = sys.stderr
        sys.stderr = open('/dev/null', 'w')

        parser = argparse.ArgumentParser(epilog=USAGE, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('--mgmt-vip')
        parser.add_argument('--mgmt-inner-vip')
        parser.add_argument('--ext-dns', nargs='+', default=[], help='Set external DNS servers. Up to 2 servers are supported, seperated by spaces')
        parser.add_argument('--ext-dns-domain', nargs='+', default=[], help='Set domain for external DNS servers')
        parser.add_argument('--only-generate-conf-files', action='store_true', default=False, help='Only generating config files without disrupting the network service')
        parser.add_argument('--dockerd-bip', help='dockerd bridge ip (ip or ip/subnet-bits is acceptable)', required=False, default=None)

        args = parser.parse_args()
        if args.mgmt_vip or args.mgmt_inner_vip:
            return parser

        if args.ext_dns or args.ext_dns_domain:
            if args.ext_dns:
                update_params['ext_dns'] = args.ext_dns

            if args.ext_dns_domain:
                update_params['ext_dns_domain'] = args.ext_dns_domain

            return parser

    except:
        pass
    finally:
        #Restore stdout + stderr
        sys.stdout = _stdout
        sys.stderr = _stderr

    parser = argparse.ArgumentParser(epilog=USAGE, formatter_class=argparse.RawDescriptionHelpFormatter)
    if not optional_only:
        parser.add_argument('node', help='node number to deduce ip addresses from')
    else:
        # This is meant only for parsing from file
        parser.add_argument('--node')
    parser.add_argument('--port-mode', type=str, help='''
update NIC firmware configuration
comma separated list of "type=mode" pairs in order of PCI enumeration
valid types: internal / external (enable/disable SRIOV)
valid modes: eth / ib
for backward compatibility it also supports a simple string with NIC mode: eth / ib
examples: 1. internal=eth 2. internal=ib 3. external=ib,internal=eth 4. eth 5. ib'''.strip())
    parser.add_argument('--template', default='172.16.{network}.{node}')
    parser.add_argument('--data-netmask', default='255.255.255.0')
    parser.add_argument('--subsystem', type=int, default=0, help='''
subsystem number will be added to the subnet in the third octet of the ip.
The netmask will determine what bits will be used for the subnet and the subsystem
will determine the value of the remaining bits'''.strip())
    parser.add_argument('--data-vlan', default=69)
    parser.add_argument('--ext-interface', help='external ip interface')
    parser.add_argument('--ext-ip')
    parser.add_argument('--ext-netmask')
    parser.add_argument('--ext-gateway')
    parser.add_argument('--ext-dns', nargs='+', default=[], help='Set external DNS servers. Up to 2 servers are supported, seperated by spaces')
    parser.add_argument('--ext-dns-domain', nargs='+', default=[], help='Set domain for external DNS servers')
    parser.add_argument('--ext-rp-filter', type=str, choices=['0', '1', '2'], default=None, help='Set Reverse Path filtering')
    parser.add_argument('--mgmt-vip', help='vip to be used by management. Should be the same on all nodes')
    parser.add_argument('--mgmt-inner-vip', help='inner vip to be used by management')
    parser.add_argument('--b2b-ipmi', action='store_true', help='configure IP address on local IPMI port for back-to-back IPMI networking')
    parser.add_argument('--b2b-template', default=B2B_TEMPLATE)
    parser.add_argument('--ipmi-ip', help='ipmi address to configure', required=False)
    parser.add_argument('--ipmi-netmask', help='if ignored, ext-netmask will be used', required=False)
    parser.add_argument('--ipmi-gateway', help='ipmi gateway', required=False)
    parser.add_argument('--hostname', help='hostname. The first ip address will be used as a default')
    parser.add_argument('--technician-interface', help='interface to be used by a technician using a crossover ethernet connection')
    parser.add_argument('--technician-ip', help='override the default IP used for the technician interface', default=TECHNICIAN_IP)
    parser.add_argument('--ib-mode', choices=['datagram', 'connected'], default='connected')
    parser.add_argument('--ib-mtu', type=int, help='the default value is set according to the mode')
    parser.add_argument('--eth-mtu', type=int, default=9216)
    parser.add_argument('--nb-ib-mode', choices=['datagram', 'connected'], default=None)
    parser.add_argument('--nb-ib-mtu', type=int, default=None)
    parser.add_argument('--nb-eth-mtu', type=int, default=None)
    parser.add_argument('--only-fw', action='store_true')
    parser.add_argument('--skip-fw', action='store_true')
    parser.add_argument('--internal-interfaces', type=str)
    parser.add_argument('--internal-virtual-interfaces', type=str)
    parser.add_argument('--external-interfaces', type=str)
    parser.add_argument('--ntp', nargs='+', help='Override default NTP servers with an explicit set. Multiple serveres are supported, seperated by spaces')
    parser.add_argument('--skip-sshd', action='store_true')
    parser.add_argument('--retain-ipv6', action='store_true', default=False)
    parser.add_argument('--auto-ports', choices=['eth', 'ib', 'int_eth_ext_ib', 'int_ib_ext_eth', 'disabled'], default='disabled', help='detect & configure ports automatically per-chassis')
    parser.add_argument('--auto-ports-ext-iface', choices=['inband', 'outband', 'bond'], default='outband', help='detect & configure ext_interface to outband or inband')
    parser.add_argument('--auto-ports-reverse-nics', action='store_true', help='Switch roles between the NIC meant for northband traffic and the NIC meant for internal traffic')
    parser.add_argument('--reverse-alias', choices=['no', 'ports', 'ips'], default='no', help='Use with caution; You probably want --auto-ports instead')
    parser.add_argument('--auto-ports-skip-nic', choices=['int', 'ext', 'none'], default='none', help='Allow auto-ports to skip one of the NICs in case a 2-NIC chassis')
    parser.add_argument('--only-generate-conf-files', action='store_true', default=False, help='Only generating config files without disrupting the network service')
    parser.add_argument(ARGLESS_RUN_PARAM, action='store_true', help='reconfigure setting using configuration stored in {}'.format(CFG_FILE))
    parser.add_argument('--dockerd-bip', help='dockerd bridge ip (ip or ip/subnet-bits is acceptable)', required=False, default=None)
    parser.add_argument('--fresh-install', action='store_true', help='indicate this is a fresh installation and existing host configuration should be ignored')
    parser.add_argument('--enable-pfc', action='store_true', default=False, help='Configure PFC on external devices based on traffic class')
    parser.add_argument('--traffic-class', type=str, help='Configure PFC on specific traffic classes, must specify value for all 8 traffic classes, x,x,x,x,x,x,x,x')
    return parser

def conf_interface(res, params, template, interfaces, ips=(None, None)):
    for interface, ip in zip(interfaces, ips):
        interface_data = interface_templates.get(template).format(interface=interface.name, mac=interface.mac, ip=ip, **params).strip()
        res[interface.name] = get_auto_generated_line(template.value) + interface_data
        # Add conditional fields
        if "DNS1" in res[interface.name] and params["ext_dns_domain"]:
            res[interface.name] += os.linesep + 'DOMAIN="' + ' '.join(params["ext_dns_domain"]) + '"'
        if "retain_ipv6" in params and params["retain_ipv6"]:
            try:
                ifcfg = IfcfgScriptFile.read(INTERFACE_CONFIG_FILE_TEMPLATE.format(interface.name))
                if ifcfg.ipv6addr:
                    res[interface.name] += os.linesep + 'IPV6ADDR=' + ifcfg.ipv6addr
            except FileNotFoundError as e:
                pass

def calc_node_location(node_type):
    if node_type == "VAST_CNODE":
        output = subprocess.check_output(['sudo', 'ipmitool', 'raw', '0x3e', '0x50']).decode('ascii').split()
        return(str( int((int(output[0])-20)/2) + 1) )

    if node_type == "VAST_DNODE":
        output = subprocess.check_output(['sudo', 'ipmitool', 'raw', '0x3c', '0x0e']).decode('ascii').split()
        return(str(int(output[1])+1))
    

def get_internal_ips(args):
    subnet_bits_shift = get_netmask_bits_position(args.data_netmask)
    assert args.subsystem < 2 ** subnet_bits_shift, f'subsystem={args.subsystem} is too large for netmask={args.data_netmask}'

    # for legacy purposes. in non-scaled systems, the subnets were 1,2,3.
    subnet_range = range(1, 4) if args.data_netmask == "255.255.255.0" else range(3)
    data_ip1, data_ip2, mgmt_ip = [args.template.format(node=args.node, network=(i << subnet_bits_shift)+args.subsystem) for i in subnet_range]
    return data_ip1, data_ip2, mgmt_ip

def udev_ib_rules(interfaces):
    udev_lines=[]
    for interface in interfaces:
        udev_lines.append(IB_UDEV_RULE.format(interface=interface.name, mac=":".join(interface.mac.split(':')[-8:])))

    with open(UDEV_IB_RULES_FILE, 'w') as udev_file:
        udev_file.writelines(udev_lines)

def configure_rp_filter(interface, rp_filter):
    assert os.system('/sbin/sysctl -w net.ipv4.conf.%s.rp_filter=%s' % (interface, rp_filter)) == 0

def get_auto_generated_line(template_name=None):
    line = "# generated by configure_network.py (shar={}) - {}".format(
        get_script_sha1(), datetime.datetime.isoformat(datetime.datetime.now()))
    if template_name:
        line += ' - using template {}'.format(template_name)

    return line + "\n"

def write_subnets_file(args):
    ips = get_internal_ips(args)

    octat3 = (ip.split(".")[2] for ip in ips)
    with open(INTERFACE_SUBNETS_FILE, "w") as f:
        f.write("\n")
        f.write(get_auto_generated_line())

        for octat in octat3:
            f.write(f"{octat}\n")

def configure_ext_interfaces(res, args, params, external_interfaces, external_alias, interfaces):
    params = params.copy()
    if args.nb_ib_mtu:
        params.update(ib_mtu=args.nb_ib_mtu)
    if args.nb_ib_mode:
        params.update(ib_mode=args.nb_ib_mode)
        params.update(connected_mode=CONNECTED_MODE[args.nb_ib_mode])
    if args.nb_eth_mtu:
        params.update(eth_mtu=args.nb_eth_mtu)

    # configure external data interfaces
    conf_interface(res, params, InterfaceTemplates.IB_PHYS if external_interfaces[0].is_ib else InterfaceTemplates.ETH_NO_IP, external_interfaces)

    # configure external ip interface
    if args.ext_interface:
        # override default external ip interface configuration
        external_alias = Interface(name='{}:e'.format(args.ext_interface))
        if not args.ext_interface.startswith('bond'):
            ext_interface, = [i for i in interfaces if i.name == args.ext_interface]
            conf_interface(res, params, InterfaceTemplates.EXTERNAL, (ext_interface,))
        elif args.ext_interface == 'bond1':
            assert len(args.ext_slave_ifaces) == 2
            conf_interface(res, {'bond_master': args.ext_interface}, InterfaceTemplates.ETH_SLAVE,
                           [Interface(name=iface) for iface in args.ext_slave_ifaces])
            conf_interface(res, params, InterfaceTemplates.ETH_BOND, (Interface(name=args.ext_interface),))

        # ORION-24262
        if 'ext_rp_filter' in args and args.ext_rp_filter != None:
            configure_rp_filter(args.ext_interface, args.ext_rp_filter)

    conf_interface(res, params, InterfaceTemplates.EXTERNAL_ALIAS, (external_alias,), (args.ext_ip,))

def prepare_ifcfgs(args, interfaces):
    res = {}
    data_ip1, data_ip2, mgmt_ip = get_internal_ips(args)

    # validate ips
    ipaddress.ip_address(data_ip1)
    ipaddress.ip_address(data_ip2)

    for interface in interfaces:
        if interface.name == 'lo':
            continue
        logger.info('discovered network interface {} with {}'.format(interface.name, interface.vendor))
        conf_interface(res, {}, InterfaceTemplates.DISABLED_INTERFACE_TEMPLATE, (interface,))

    params = vars(args)
    params.update(connected_mode=CONNECTED_MODE[args.ib_mode])
    if not args.ib_mtu:
        params.update(ib_mtu=DEFAULT_IB_BOND_MTU[args.ib_mode])
    while len(args.ext_dns) < 2:
        params["ext_dns"].append('')
    params["ext_bond_dns"] = params["ext_dns"] if params["ext_interface"] == "bond0" else ['', '']
    # choose the configuration mode
    if not args.internal_interfaces:
        # select internal interfaces manually
        eth_phys = filter_ifs(interfaces, vendor=InterfaceVendor.Mellanox, is_virtual=False, is_ib=False)
        ib_phys = filter_ifs(interfaces, vendor=InterfaceVendor.Mellanox, is_virtual=False, is_ib=True)

        if len(eth_phys) == 2 and len(ib_phys) == 0:
            # eth only
            args.internal_interfaces = args.external_interfaces = interfaces_to_arg(eth_phys)
            args.internal_virtual_interfaces = interfaces_to_arg(filter_ifs(interfaces, vendor=InterfaceVendor.Mellanox, is_virtual=True, is_ib=False))
        elif len(eth_phys) == 0 and 0 < len(ib_phys):
            # ib 2 ports
            args.internal_interfaces = args.external_interfaces = interfaces_to_arg(ib_phys)
        else:
            assert False, "MIXED mode detected (more than 1 NIC). please specify internal and external interfaces"

    internal = interfaces_from_arg(interfaces, args.internal_interfaces)
    external = interfaces_from_arg(interfaces, args.external_interfaces)
    internal_virtual = interfaces_from_arg(interfaces, args.internal_virtual_interfaces)

    # configure internal interfaces
    port_order = 'ba' if args.reverse_alias == 'ports' else 'ab'
    alias_ips = (data_ip2, data_ip1) if args.reverse_alias == 'ips' else (data_ip1, data_ip2)

    if not internal[0].is_ib:
        # eth only
        assert len(internal) == 2
        assert len(internal_virtual) == 2

        eth_vlan = [Interface(name='{}.{}'.format(i.name, args.data_vlan), mac=i.mac) for i in internal]
        eth_vlan_alias = [Interface(name='{}:{}'.format(i.name, c)) for i, c in zip(eth_vlan, port_order)]
        vlan_bond = 'bond0.{}'.format(args.data_vlan)
        conf_interface(res, params, InterfaceTemplates.ETH_NO_IP, internal)
        conf_interface(res, {'bond_master': 'bond0'}, InterfaceTemplates.ETH_SLAVE, internal_virtual)
        conf_interface(res, params, InterfaceTemplates.ETH_BOND, (Interface(name='bond0'),))
        conf_interface(res, params, InterfaceTemplates.ETH_VLAN, eth_vlan)
        conf_interface(res, params, InterfaceTemplates.ALIAS, eth_vlan_alias, alias_ips)
        conf_interface(res, params, InterfaceTemplates.ETH_BOND_VLAN, (Interface(name=vlan_bond),))
        conf_interface(res, params, InterfaceTemplates.ALIAS, (Interface(name='{}:m'.format(vlan_bond)),), (mgmt_ip,))
        external_alias = Interface(name='bond0:e')

        udev_ib_rules([]) # Clean any previous IB-related rule
    elif len(internal) == 1:
        # ib 1 port
        ib_alias = [Interface(name='{}:{}'.format(internal[0].name, c)) for c in port_order]

        conf_interface(res, params, InterfaceTemplates.IB_PHYS, internal)
        udev_ib_rules(internal)
        conf_interface(res, params, InterfaceTemplates.ALIAS, ib_alias, alias_ips)
        conf_interface(res, params, InterfaceTemplates.ALIAS, (Interface(name='{}:m'.format(internal[0].name)),), (mgmt_ip,))
        external_alias = Interface(name='{}:e'.format(internal[0].name))
    elif len(internal) == 2:
        # ib 2 ports
        ib_alias = [Interface(name='{}:{}'.format(i.name, c)) for i, c in zip(internal, port_order)]
        ib_virt = filter_ifs(interfaces, vendor=InterfaceVendor.Mellanox, is_virtual=True, is_ib=True)
        assert len(ib_virt) == 2

        conf_interface(res, params, InterfaceTemplates.IB_PHYS, internal)
        udev_ib_rules(internal)
        conf_interface(res, params, InterfaceTemplates.ALIAS, ib_alias, alias_ips)
        conf_interface(res, params, InterfaceTemplates.IB_SLAVE, ib_virt)
        conf_interface(res, params, InterfaceTemplates.IB_BOND, (Interface(name='bond0'),))
        conf_interface(res, params, InterfaceTemplates.ALIAS, (Interface(name='bond0:m'),), (mgmt_ip,))
        external_alias = Interface(name='bond0:e')

    configure_ext_interfaces(res, args, params, external, external_alias, interfaces)

    if args.technician_interface:
        technician_interfaces = [i for i in interfaces if i.name == args.technician_interface]
        conf_interface(res, params, InterfaceTemplates.TECHNICIAN, technician_interfaces, (args.technician_ip,))

    return res


def validate_ip_args(args):
    if not args.ext_ip:
        print("ERROR: External IP address is missing")
        return False
    if not args.ext_netmask:
        print("ERROR: External netmask is missing")
        return False

    try:
        net = ipaddress.IPv4Network((args.ext_ip, args.ext_netmask), strict=False)
    except ipaddress.AddressValueError:
        print(f"ERROR: External IP address is not valid (ip: {args.ext_ip})")
        return False
    except ipaddress.NetmaskValueError:
        print(f"ERROR: External netmask is not valid (ip: {args.ext_ip}, netmask: {args.ext_netmask})")
        return False

    if args.ext_gateway:
        try:
            gw = ipaddress.IPv4Address(args.ext_gateway)
        except ipaddress.AddressValueError:
            print(f"ERROR: external gateway address is not valid (gw: {args.ext_gateway})")
            return False

        if gw not in net:
            print(f"ERROR: extenal gateway address in not in current network according to IP and netmask (ip: {args.ext_ip}, netmask: {args.ext_netmask}, gw: {args.ext_gateway})")
            return False

    return True

AUTO_PORTS_MAPPINGS = [
    (
        {"02:00.0": {"nic_location": HWLocation.LEFT, "port_location": HWLocation.RIGHT},
         "02:00.1": {"nic_location": HWLocation.LEFT, "port_location": HWLocation.LEFT}},
        "Broadwell, single dual-port NIC",
        {
            'eth': {'int': 'ens785f0,ens785f1', 'ext': 'ens785f0,ens785f1', 'virt': 'ens785f2,ens785f3', 'rev': 'no'},
            'ib': {'int': 'ib0,ib1', 'ext': 'ib0,ib1', 'virt': 'ib2,ib3', 'rev': 'no'}
        },
        {'ext_interface': {'outband': {'b2b': 'eno2', 'default': 'eno1'}, 'inband': 'bond0', 'bond': 'bond1'}},
        {'tech_interface': {'b2b': 'eno1', 'default': 'eno2'}}
    ),

    # For all CascadeLake flavours, 5e:00.x would ALWAYS be the internal port
    (
        {"3b:00.0": {"nic_location": HWLocation.LEFT, "port_location": HWLocation.RIGHT},
         "3b:00.1": {"nic_location": HWLocation.LEFT, "port_location": HWLocation.LEFT},
         "5e:00.0": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.LEFT},
         "5e:00.1": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.RIGHT}},
        "CascadeLake, two dual-port NICs",
        {
            'eth': {'int': 'enp94s0f0,enp94s0f1', 'ext': 'enp59s0f0,enp59s0f1', 'virt': 'enp94s0f2,enp94s0f3',
                    'rev': 'ips',
                    'rev_int': 'enp59s0f0,enp59s0f1', 'rev_ext': 'enp94s0f0,enp94s0f1',
                    'rev_virt' : 'enp59s0f2,enp59s0f3'},
            'ib': {'int': 'ib2,ib3', 'ext': 'ib0,ib1', 'virt': 'ib4,ib5', 'rev': 'ips',
                    'rev_int': 'ib0,ib1', 'rev_ext':'ib2,ib3', 'rev_virt':'ib4,ib5'},
            'int_ib_ext_eth': {'int': 'ib0,ib1', 'ext': 'enp59s0f0,enp59s0f1', 'virt': 'ib2,ib3', 'rev': 'ips',
                                'rev_int': 'ib0,ib1', 'rev_ext': 'enp94s0f0,enp94s0f1', 'rev_virt': 'ib2,ib3'},
            'int_eth_ext_ib': {'int': 'enp94s0f0,enp94s0f1', 'ext': 'ib0,ib1', 'virt': 'enp94s0f2,enp94s0f3',
                                'rev': 'ips',
                                'rev_int': 'enp59s0f0,enp59s0f1', 'rev_ext': 'ib0,ib1',
                                'rev_virt': 'enp59s0f2,enp59s0f3'}
        },
        {'ext_interface': {'outband': {'b2b': 'eno2', 'default': 'eno1'}, 'inband': 'bond0', 'bond': 'bond1'}},
        {'tech_interface': {'b2b': 'eno1', 'default': 'eno2'}}
    ),

    (
        {"5e:00.0": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.LEFT},
         "5e:00.1": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.RIGHT}},
        "CascadeLake, single dual-port NIC",
        {
            'eth': {'int': 'enp94s0f0,enp94s0f1', 'ext': 'enp94s0f0,enp94s0f1', 'virt': 'enp94s0f2,enp94s0f3', 'rev': 'ips'},
            'ib': {'int': 'ib0,ib1', 'ext': 'ib0,ib1', 'virt': 'ib2,ib3', 'rev': 'ips'}
        },
        {'ext_interface': {'outband': {'b2b': 'eno2', 'default': 'eno1'}, 'inband': 'bond0', 'bond': 'bond1'}},
        {'tech_interface': {'b2b': 'eno1', 'default': 'eno2'}}
    ),

    (
        # Need to support both regular mapping and mapping in case PCM is that of dual-port NIC
        [ {"11:00.0": {"nic_location": HWLocation.LEFT, "port_location": HWLocation.SINGLE},
           "92:00.0": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.SINGLE}},
          {"19:00.0": {"nic_location": HWLocation.LEFT, "port_location": HWLocation.SINGLE},
           "9a:00.0": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.SINGLE}} ],
        "Sanmina, two single-port NICs",
        {
            'eth': {'int': 'ens3,ens14', 'ext': 'ens3,ens14', 'virt': 'ens3f1,ens14f1', 'rev': 'ports'},
            'ib': {'int': 'ib0,ib1', 'ext': 'ib0,ib1', 'virt': 'ib2,ib3', 'rev': 'ips'}
        },
        {'ext_interface': {'outband': {'b2b': 'ens4', 'default': 'ens6'}, 'inband': 'bond0', 'bond': 'bond1'}},
        {'tech_interface': {'b2b': 'ens6', 'default':'ens4'}}
    ),

    (
        {"9a:00.0": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.RIGHT},
         "9a:00.1": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.LEFT}},
        "Sanmina, single dual-port NIC",
        {
            'eth': {'int': 'ens14f0,ens14f1', 'ext': 'ens14f0,ens14f1', 'virt': 'ens14f2,ens14f3', 'rev': 'no'},
            'ib': {'int': 'ib0,ib1', 'ext': 'ib0,ib1', 'virt': 'ib2,ib3', 'rev': 'no'}
        },
        {'ext_interface': {'outband': {'b2b': 'ens4', 'default': 'ens6'}, 'inband': 'bond0', 'bond': 'bond1'}},
        {'tech_interface': {'b2b': 'ens6', 'default':'ens4'}}
    ),

    (
        {"82:00.0": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.RIGHT},
         "82:00.1": {"nic_location": HWLocation.RIGHT, "port_location": HWLocation.LEFT}},
        "Supermicro, single dual-port NIC",
        {
            'eth': {'int': 'enp130s0f0,enp130s0f1', 'ext': 'enp130s0f0,enp130s0f1', 'virt': 'enp130s0f2,enp130s0f3', 'rev': 'no'},
            'ib': None
        },
        {'ext_interface': {'outband': {'b2b': 'enp2s0f1', 'default':'enp2s0f0'}, 'inband': 'bond0', 'bond': 'bond1'}},
        {'tech_interface': {'b2b': 'enp2s0f0', 'default':'enp2s0f1'}}
    )
]

def auto_ports(args):
    # Validate derived parameters were not provided
    if not args.load_params_from_file:
        if args.internal_interfaces != None:
            logger.warning("--auto-ports makes --internal-interfaces obsolete")
        if args.internal_virtual_interfaces != None:
            logger.warning("--auto-ports makes --internal-virtual-interfaces obsolete")
        if args.external_interfaces != None:
            logger.warning("--auto-ports makes --external-interfaces obsolete")
        if args.port_mode:
            logger.warning("--auto-ports makes --port-mode obsolete")
        if args.reverse_alias != 'no':
            logger.warning("--auto-ports makes --reverse-alias obsolete")
        if args.ext_interface != None:
            logger.warning("--auto-ports makes --ext-interface obsolete")

    # Discover the current chassis
    devices = subprocess.check_output(['lspci']).decode('ascii').strip().split('\n')
    bdfs = set([device.split()[0] for device in devices if "Mellanox" in device])

    for b, s, d, a, t in AUTO_PORTS_MAPPINGS:
        if isinstance(b, list):
            for busses in b:
                if set(busses.keys()).issubset(bdfs):
                    break
            else:
                continue
        elif not set(b.keys()).issubset(bdfs):
            continue

        logger.info(f'auto-ports configuration: {s}')

        if args.auto_ports_reverse_nics and len(b) <= 2:
            _exit(f"can't reverse NIC roles on a cluster without two dual-port NICs")

        if args.auto_ports not in d:
            _exit(f"Can't find '{args.auto_ports}' for '{s}'")
        p = d[args.auto_ports]
        if not p:
            _exit(f"Need to fill-in missing information regarding '{args.auto_ports}' for '{s}'")

        if not args.auto_ports_reverse_nics:
            if args.auto_ports_skip_nic == 'none':
                args.internal_interfaces = p['int']
                args.internal_virtual_interfaces = p['virt']
                args.external_interfaces = p['ext']
            elif args.auto_ports_skip_nic == 'ext':
                args.internal_interfaces = p['int']
                args.internal_virtual_interfaces = p['virt']
                args.external_interfaces = p['int']
            elif args.auto_ports_skip_nic == 'int':
                args.internal_interfaces = p['ext']
                if not 'rev_virt' in p:
                    _exit(f"{s} doesn't support disabling internal NIC")
                args.internal_virtual_interfaces = p['rev_virt']
                args.external_interfaces = p['ext']
            else:
                _exit(f"unexpected value of --auto-ports-skip-nic={args.auto_ports_skip_nic}")
            args.reverse_alias = p['rev']
        else:
            args.internal_interfaces = p['rev_int']
            args.internal_virtual_interfaces = p['rev_virt']
            args.external_interfaces = p['rev_ext']
            args.reverse_alias = 'no'

        if args.auto_ports_ext_iface == 'outband':
            args.ext_interface = a['ext_interface']['outband']['b2b'] if args.b2b_ipmi else a['ext_interface']['outband']['default']
        else:
            args.ext_interface = a['ext_interface'][args.auto_ports_ext_iface]

        args.technician_interface = t['tech_interface']['b2b'] if args.b2b_ipmi else t['tech_interface']['default']

        if args.auto_ports_ext_iface == 'bond':
            # we don't support bond on mgmt network with tech interface
            args.technician_interface = None
            ext_slave_ifaces = getattr(args, 'ext_slave_ifaces', None)
            if ext_slave_ifaces is None:
                setattr(args, 'ext_slave_ifaces', list(a['ext_interface']['outband'].values()))
            assert len(args.ext_slave_ifaces) == 2

        # This one is a bit tricky for the ib/eth combinations. Since the actual usage of by configure_network would
        # apply the configuration according to PCI enumeration, the first to appear has to be the one matching the lower
        # BDF, i.e. internal=eth,external=ib and external=ib,internal=eth would lead to different results. We might
        # want to simplify this in future
        args.port_mode = {
            'eth': 'external=eth,internal=eth',
            'ib': 'external=ib,internal=ib',
            'int_ib_ext_eth': 'external=eth,internal=ib',
            'int_eth_ext_ib': 'external=ib,internal=eth'
        }[args.auto_ports]
        break
    else:
        _exit(f"Can't recognize chassis based on Mellanox adapters in {bdfs}. Please provide manual configuration (without --auto-ports)")


class CfgHandler:
    def __init__(self, file=None):
        self._file = file if file else CFG_FILE

    def write(self, args):
        # Some configurations shouldn't persist
        prev_fresh_install = args.fresh_install
        args.fresh_install = False

        with open(self._file, 'w') as f:
            f.write('# generated by configure_network.py (sha1={})- {}\n'.format(
                get_script_sha1(), datetime.datetime.isoformat(datetime.datetime.now())))
            for k, v in args._get_kwargs():
                f.write('{}={}\n'.format(k, v))

        args.fresh_install = prev_fresh_install

    def read(self, args, require_key_to_exist=True):
        try:
            with open(self._file, 'r') as f:
                for line in f:
                    if "=" not in line:
                        continue

                    k, v = line.strip().split("=", 1)

                    if not require_key_to_exist or k in args.__dict__.keys():
                        try:
                            args.__dict__[k] = eval(v)
                        except:
                            # ORION-27691: Old versions might have save lists as single entries
                            if k in args.__dict__.keys() and args.__dict__[k] == []:
                                args.__dict__[k].append(v)
                            else:
                                args.__dict__[k] = v
        except OSError as e:
            _exit(f"failed to open {self._file}: {str(e)}")
        except Exception as e:
            logger.exception(str(e))
            _exit(f"failed in cfg-file parsing: {str(e)}")

def clean_b2b_ipmi_args_rerun(args):
    '''
    clean arguments conflicting with b2b_ipmi in case it is a rerun
    '''
    assert args.load_params_from_file and args.b2b_ipmi
    args.technician_ip = TECHNICIAN_IP
    args.ipmi_ip = None
    args.ipmi_gateway = None

def validate_b2b_ipmi_args(args):
    error_message = []
    if not args.technician_interface in B2B_ALLOWED_INTERFACES:
        error_message.append("Error: option --technician-interface has invalid value or is missing value")
    if args.technician_ip not in TECHNICIAN_IP:
        error_message.append("options --b2b-ipmi and --technician-ip are mutual exclusive, only one of them is allowed")
    if args.ipmi_ip:
        error_message.append("options --b2b-ipmi and --ipmi-ip are mutual exclusive, only one of them is allowed")
    if args.ipmi_gateway:
        error_message.append("options --b2b-ipmi and --ipmi-gateway are mutual exclusive, only one of them is allowed")

    for message in error_message:
        logger.error(message)
    assert not error_message, 'invalid b2b ipmi args'

def validate_b2b_ipmi_node_product_name():
    '''b2b ipmi is only supported on Vast supplied hardware'''
    try:
        output_list = subprocess.check_output(['sudo', 'ipmitool', 'fru', 'list']).decode('ascii').splitlines()
    except Exception as e:
        output_list = e.stdout.splitlines()

    node_type = None

    for product_name in B2B_ALLOWED_CNODE_PRODUCT_NAME:
        search_str = 'Product Name.*' + product_name
        for item in output_list:
            if re.search(search_str, str(item)):
                node_type = "VAST_CNODE"

    for product_name in B2B_ALLOWED_DNODE_PRODUCT_NAME:
        search_str = 'Product Name.*' + product_name
        for item in output_list:
            if re.search(search_str, str(item)):
                node_type = "VAST_DNODE"

    assert node_type in ["VAST_CNODE", "VAST_DNODE"], 'Unknown hardware type - B2B IPMI configuration is not supported'

    node_location = calc_node_location(node_type)
    logger.info('Discovered this is a {} {}'.format(node_type,node_location))
    return node_type, node_location


def format_dockerd_bip_address(dockerd_bip):
    if '/' not in dockerd_bip:
        dockerd_bip = f'{dockerd_bip}/{DOCKER_DEFAULT_BRIDGE_IP_SUBNET_BITS}'
    return dockerd_bip
    

def validate_net_args(args):
    """
    validate no net overlap between the node internal addresses and dockerd bridge ip
    """
    dockerd_bip = getattr(args, 'dockerd_bip', None)
    template = getattr(args, 'template', None)

    if not template:
        return

    dockerd_bip = dockerd_bip if dockerd_bip else DOCKER_DEFAULT_BRIDGE_IP
    dockerd_bip = format_dockerd_bip_address(dockerd_bip)
    dockerd_ip_iface = ipaddress.ip_interface(dockerd_bip)

    for node_ip in get_internal_ips(args):
        node_ip_iface = ipaddress.ip_interface(f'{node_ip}/{DEFAULT_IP_SUBNET_BITS}')
        assert not dockerd_ip_iface.network.overlaps(node_ip_iface.network), (
            f'invalid args: template={args.template} and dockerd-bip={dockerd_bip} '
            f'will cause network overlap between {dockerd_ip_iface} and {node_ip_iface}')


def sanitize_args(args):
    if args.auto_ports == 'disabled':
        if args.auto_ports_reverse_nics:
            logger.warning("--auto-ports-reverse-nics is meaningless without --auto-ports; disabling")
            args.auto_ports_reverse_nics = False

    if args.auto_ports_reverse_nics and args.auto_ports_skip_nic != 'none':
        _exit(f"can't use --auto-ports-reverse-nics and --auto-ports-skip-nic combined")

    if args.auto_ports_skip_nic != "none" and args.auto_ports in {'int_eth_ext_ib', 'int_ib_ext_eth'}:
        _exit(f"can't use --auto-ports-skip-nic with --auto-ports={args.auto_ports}")

    if args.auto_ports_ext_iface == 'bond' and args.b2b_ipmi:
        _exit("can't use --auto-ports-ext-iface=bond with --b2b-ipmi")


def handle_mgmt_args(args):
    os.makedirs(VMAN_DIR, exist_ok=True)
    vastdata_user = pwd.getpwnam('vastdata')
    os.chown(VMAN_DIR, vastdata_user.pw_uid, vastdata_user.pw_gid)
    os.chmod(VMAN_DIR, 0o755)

    if args.mgmt_vip:
        with open(MGMT_VIP_FILE, 'w') as mgmt_vip_file:
            mgmt_vip_file.write(args.mgmt_vip)
        os.chown(MGMT_VIP_FILE, vastdata_user.pw_uid, vastdata_user.pw_gid)
        update_etc_hosts(hosts_records={LOCAL_DOCKER_REGISTRY_NAME: args.mgmt_vip})
        if not hasattr(args, 'node'):
            ips = [args.mgmt_vip]
            update_sshd_config(*ips, erase_existing = False)

    if args.mgmt_inner_vip:
        with open(MGMT_INNER_VIP_FILE, 'w') as mgmt_inner_vip_file:
            mgmt_inner_vip_file.write(args.mgmt_inner_vip)
        os.chown(MGMT_INNER_VIP_FILE, vastdata_user.pw_uid, vastdata_user.pw_gid)


def main(args, rerun, iface_path_to_mtu=None):
    validate_net_args(args)

    handle_mgmt_args(args)

    # update dockerd related configs
    changed = update_docker_configs(args)
    if changed and not args.only_generate_conf_files:
        os.system('service docker reload')

    if not rerun and not hasattr(args, 'node') and (hasattr(args, 'mgmt_vip') or hasattr(args, 'mgmt_inner_vip')):
        #in this case only mgmt-vip and/or mgmt-inner-vip are the option that were called so we are done
        return

    sanitize_args(args)

    if args.auto_ports != 'disabled':
        auto_ports(args)

    if args.b2b_ipmi:
        if args.load_params_from_file:
            clean_b2b_ipmi_args_rerun(args)
        validate_b2b_ipmi_args(args)
        node_type, node_location = validate_b2b_ipmi_node_product_name()
        b2b_technician_ip = args.b2b_template.format(node=node_location)
        b2b_ipmi_ip = args.b2b_template.format(node=(int(node_location) + 10))

        ''' Modify values of command line arguments for b2b ipmi network'''
        setattr(args, "technician_ip", b2b_technician_ip)
        setattr(args, "ipmi_ip", b2b_ipmi_ip)
        setattr(args, "ipmi_netmask", "255.255.255.0")
        setattr(args, "ipmi_gateway", b2b_technician_ip)

    if not args.skip_fw:
        configure_fw(args)
    if args.only_fw:
        return

    if not validate_ip_args(args):
        print("external ip arguments are not valid, aborting")
        return

    interfaces = get_interfaces()
    ifcfgs = prepare_ifcfgs(args, interfaces)

    for file in os.listdir(INTERFACE_CONFIG_DIR):
        if not file.startswith('ifcfg-') or file == 'ifcfg-lo':
            continue
        logger.info('discovered network interface config {}'.format(file))
        backup_file(INTERFACE_CONFIG_DIR, file)

    for interface, ifcfg in ifcfgs.items():
        path = INTERFACE_CONFIG_FILE_TEMPLATE.format(interface)
        logger.info('creating file {} for interface: {}'.format(path, interface))
        with open(path, 'w') as f:
            f.write(ifcfg)
            f.flush()
            os.fsync(f.fileno())

    if rerun and iface_path_to_mtu:
        logger.info('reconfiguring pre-configured MTU values')
        for ifcfg_path, mtu in iface_path_to_mtu.items():
            write_kv_to_ifcfg(ifcfg_path, 'MTU', mtu)

    configure_hostname(args.hostname if args.hostname else 'node-' + str(args.node))
    write_subnets_file(args)

    eth_interfaces = filter_ifs(interfaces, vendor=InterfaceVendor.Mellanox, is_virtual=False, is_ib=False)
    ib_interfaces = filter_ifs(interfaces, vendor=InterfaceVendor.Mellanox, is_virtual=False, is_ib=True)
    ext_interfaces = filter_ifs(interfaces, name=args.ext_interface)

    if not args.only_generate_conf_files:
        # flush old ips
        for interface in interfaces:
            if interface.vendor == InterfaceVendor.NONE and '.' in interface.name:
                logger.info('deleting vlan link: {}'.format(interface))
                assert os.system('ip link del ' + interface.name) == 0
        for i in ib_interfaces + eth_interfaces + ext_interfaces:
            assert os.system('ip addr flush dev {}'.format(i.name)) == 0

        for i in ib_interfaces:
            assert os.system('grep {1} /sys/class/net/{0}/mode > /dev/null || echo {1} >/sys/class/net/{0}/mode'.format(i.name, args.ib_mode)) == 0

    if args.ntp:
        assert os.system('sed -i "s/^server/#server/" /etc/chrony.conf') == 0
        for server in args.ntp:
            assert os.system("sed -i '1s/^/server {} iburst\\n/' /etc/chrony.conf".format(server)) == 0
        if not args.only_generate_conf_files:
            assert os.system('systemctl restart chronyd') == 0

    if args.enable_pfc and not args.load_params_from_file:
        logger.info('enabling priority-flow-control for traffic class: {}'.format(args.traffic_class))
        assert args.external_interfaces != args.internal_interfaces, "cannot configure PFC when internal interfaces are the same as external interfaces"
        assert len(args.traffic_class.split(',')) == 8, "must specify value for all 8 traffic classes, x,x,x,x,x,x,x,x"
        for tc in args.traffic_class.split(','):
            assert tc == '0' or tc == '1', "traffic class must be 0 or 1"
        with open(MLX_POST_OPENIBD_CONFIGURE_FILE, 'a') as f:
            f.write('\n')
            for interface in args.external_interfaces.split(','):
                mlx_interface = extract_mlx_interface(interface)
                cmd = 'mlnx_qos -i %s --trust dscp\n' % interface
                assert os.system(cmd) == 0
                f.write(cmd)
                cmd = 'mlnx_qos -i %s --pfc %s\n' % (interface, args.traffic_class)
                assert os.system(cmd) == 0
                f.write(cmd)
                cmd = 'bash -c "echo 106 > /sys/class/infiniband/%s/tc/1/traffic_class"\n' % mlx_interface
                assert os.system(cmd) == 0
                f.write(cmd)
                cmd = 'cma_roce_tos -d %s -t 106\n' % mlx_interface
                assert os.system(cmd) == 0
                f.write(cmd)

    if args.ipmi_ip and not args.only_generate_conf_files:
        ipmi_gateway = args.ipmi_gateway or args.ext_gateway
        ipmi_netmask = args.ipmi_netmask or args.ext_netmask
        configure_ipmi(args.ipmi_ip, ipmi_netmask, ipmi_gateway)

    if not args.only_generate_conf_files:
        os.system('pkill -f dhclient')
        os.system('rm /etc/resolv.conf')
        os.system('modprobe -r bonding') # bonding driver requires reloading when switching IB/ETH
        assert os.system('udevadm control --reload-rules') == 0
        assert os.system('systemctl restart network') == 0
        assert os.system('systemctl restart docker') == 0 # our services need to re-bind ports

        # Validate both services started correctly
        assert os.system('systemctl is-active network > /dev/null 2>&1') == 0
        assert os.system('systemctl is-active docker > /dev/null 2>&1') == 0

    if not args.skip_sshd:
        ips = [LOCALHOST_IP, args.ext_ip, args.technician_ip]
        ips += get_internal_ips(args)
        if args.mgmt_vip:
            ips.append(args.mgmt_vip)
        update_sshd_config(*ips)
        if not args.only_generate_conf_files:
            assert os.system('systemctl restart sshd') == 0

    # Write the configuration file - but we don't want to lose the original in case of a re-run
    handle = CFG_FILE
    if rerun:
        handle += "-" + datetime.date.isoformat(datetime.datetime.now())
    CfgHandler(handle).write(args)

def update_dns_params(args):
    params = vars(args)
    resolv_conf_file_path = RESOLV_CONF_FILE
    resolv_conf_file_path_temp = resolv_conf_file_path + '.tmp'
    with open(resolv_conf_file_path_temp, 'w') as outfile:
        if args.ext_dns:
            for ext_dns in params['ext_dns']:
                if len(ext_dns) == 0:
                    continue

                outfile.write('nameserver {}\n'.format(ext_dns))
                logger.info('Updating new dns nameserver: {}'.format(ext_dns))

        if args.ext_dns_domain:
            outfile.write('search {}\n'.format(params["ext_dns_domain"]))
            logger.info('Updating new dns search entry: {}'.format(params["ext_dns_domain"]))

    shutil.move(resolv_conf_file_path_temp, resolv_conf_file_path)

if __name__ == '__main__':
    # use logs file handler only when runs as script, so it will not crash unittests
    os.makedirs(LOG_DIR, exist_ok=True)
    file_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'configure_network.log'),
                                       maxBytes=10000000, backupCount=5)
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    try:
        only_generate_conf_files = False
        rerun = False
        if len(sys.argv) == 2:
            rerun = ARGLESS_RUN_PARAM in sys.argv
        elif len(sys.argv) == 3:
            rerun = ARGLESS_RUN_PARAM in sys.argv and ONLY_GENERATE_CONF_FILES in sys.argv
            only_generate_conf_files = True

        assert rerun or ARGLESS_RUN_PARAM not in sys.argv, '{} should not be used with other args'.format(ARGLESS_RUN_PARAM)
        logger.info('execution mode: rerun={}'.format(rerun))

        update_params = dict()
        args = create_args_parser(update_params=update_params, optional_only=rerun).parse_args()
        logger.info(f'got execution args: {args}')

        iface_path_to_mtu = {}

        if rerun:
            CfgHandler().read(args)
            args.load_params_from_file = True
            args.only_generate_conf_files = only_generate_conf_files
            args.fresh_install = False

            # w/a for ORION-21388
            mgmt_vip = get_mgmt_vip_from_file()
            if mgmt_vip and mgmt_vip != args.mgmt_vip:
                logger.info('using mgmt-vip {}'.format(mgmt_vip))
                args.mgmt_vip = mgmt_vip

            # in case mtu was changed manually - ORION-21536
            relevant_interfaces = get_interfaces_from_args(args)
            logger.info('checking mtu on interfaces: {}'.format(relevant_interfaces))
            iface_path_to_mtu.update(get_configured_mtus(relevant_interfaces))
        elif 'ext_dns' in update_params.keys() or 'ext_dns_domain' in update_params.keys():
            # Create empty argparse args
            orig_args = argparse.ArgumentParser(
                epilog=USAGE, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args([])
            CfgHandler().read(orig_args, require_key_to_exist=False)
            if args.ext_dns:
                orig_args.ext_dns = args.ext_dns

            if args.ext_dns_domain:
                orig_args.ext_dns_domain = args.ext_dns_domain

            orig_args.only_generate_conf_files = True
            update_dns_params(orig_args)
            args = orig_args

        logger.info(f'running with args: {args}')

        # Make sure we have no leading & trailing whitespaces
        for k,v in args.__dict__.items():
            if isinstance(v, str):
                args.__dict__[k] = v.strip()

        main(args, rerun, iface_path_to_mtu)
    except Exception as e:
        logger.exception(str(e))
        raise
