#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from datetime import datetime
# noinspection PyPackageRequirements
from ipaddr import IPAddress, IPv6Address
from pprint import pformat
from uuid import uuid4

import re
import socket
import sys

import ConfigParser
import GeoIP

reload(sys)
sys.setdefaultencoding('utf-8')


def info(*objs):
    print("INFO:", *objs, file=sys.stderr)


def warning(*objs):
    print("WARNING:", *objs, file=sys.stderr)


def debug(*objs):
    print("DEBUG:\n", *objs, file=sys.stderr)


def get_date(date_string, uts=False):
    if not uts:
        return datetime.strptime(date_string, "%a %b %d %H:%M:%S %Y")
    else:
        return datetime.fromtimestamp(float(date_string))


def get_unix_time(date):
    return (date - datetime(1970, 1, 1)).total_seconds()


def get_str(s):
    if s is not None:
        return s.decode('ISO-8859-1')
    else:
        return s


class ConfigLoader(object):
    def __init__(self, config_file):
        self.settings = {}
        self.vpn = {}
        config = ConfigParser.RawConfigParser()

        contents = config.read(config_file)
        if not contents and config_file == './openvpn-monitor.conf':
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            if sys.prefix == '/usr':
                conf_path = '/etc/'
            else:
                conf_path = sys.prefix + '/etc/'
            config_file = conf_path + 'openvpn-monitor.conf'
            contents = config.read(config_file)

        if contents:
            info('Using config file: {0!s}'.format(config_file))
        else:
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            self.load_default_settings()

        for section in config.sections():
            if section == 'OpenVPN-Monitor':
                self.parse_global_section(config)
            elif section == 'VPN':
                self.parse_vpn_section(config)

    def load_default_settings(self):
        info('Using default settings => /usr/run/openvpn.default.socket')
        self.settings = {'geoip_data': '/usr/share/GeoIP/GeoIPCity.dat'}
        self.vpn = {'socket': '/var/run/openvpn.default.socket'}

    def parse_global_section(self, config):
        global_vars = ['geoip_data']
        for var in global_vars:
            try:
                self.settings[var] = config.get('OpenVPN-Monitor', var)
            except ConfigParser.NoOptionError:
                pass

    def parse_vpn_section(self, config):
        vpn_vars = ['socket']
        for var in vpn_vars:
            try:
                self.vpn[var] = config.get('VPN', var)
            except ConfigParser.NoOptionError:
                pass


class OpenvpnMonitor(object):
    def __init__(self, cfg):
        self.vpn = cfg.vpn
        self.geoip_data = cfg.settings['geoip_data']

    def __enter__(self):
        self._socket_connect(self.vpn)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.s is not None:
            self._socket_disconnect()

    def collect_data(self, vpn):
        version = self.send_command('version\n')
        vpn['version'] = self.parse_version(version)
        state = self.send_command('state\n')
        vpn['state'] = self.parse_state(state)
        stats = self.send_command('load-stats\n')
        vpn['stats'] = self.parse_stats(stats)
        status = self.send_command('status 3\n')
        vpn['sessions'] = self.parse_status(status, self.geoip_data)

    def _socket_send(self, command):
        self.s.send(command)

    def _socket_recv(self, length):
        return self.s.recv(length)

    def _socket_connect(self, vpn):
        unix_socket = vpn['socket']
        try:
            self.s = socket.socket(socket.AF_UNIX)
            self.s.settimeout(3)
            self.s.connect(unix_socket)
            vpn['socket_connected'] = True
        except socket.error:
            self.s = None
            vpn['socket-connected'] = False

    def _socket_disconnect(self):
        self._socket_send('quit\n')
        self.s.close()

    def send_command(self, command):
        self._socket_send(command)
        data = ''
        while 1:
            socket_data = self._socket_recv(1024)
            socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
            data += socket_data
            if command == 'load-stats\n' and data != '':
                break
            elif data.endswith("\nEND\r\n"):
                break
        return data

    @staticmethod
    def parse_state(data):
        state = {}
        for line in data.splitlines():
            parts = line.split(',')
            if parts[0].startswith('>INFO') or \
                    parts[0].startswith('END') or \
                    parts[0].startswith('>CLIENT'):
                continue
            else:
                # state['up_since'] = get_date(date_string=parts[0], uts=True)
                state['up_since'] = get_unix_time(get_date(date_string=parts[0], uts=True))
                state['connected'] = parts[1]
                state['success'] = parts[2]
                if parts[3]:
                    # state['local_ip'] = IPAddress(parts[3])
                    state['local_ip'] = parts[3]
                else:
                    state['local_ip'] = ''
                if parts[4]:
                    # state['remote_ip'] = IPAddress(parts[4])
                    state['remote_ip'] = parts[4]
                    state['mode'] = 'Client'
                else:
                    state['remote_ip'] = ''
                    state['mode'] = 'Server'
        return state

    @staticmethod
    def parse_stats(data):
        stats = {}
        line = re.sub('SUCCESS: ', '', data)
        parts = line.split(',')
        stats['nclients'] = int(re.sub('nclients=', '', parts[0]))
        stats['bytesin'] = int(re.sub('bytesin=', '', parts[1]))
        stats['bytesout'] = int(re.sub('bytesout=', '', parts[2]).replace('\r\n', ''))

        return stats

    @staticmethod
    def parse_status(data, geoip_data):
        client_section = False
        routes_section = False
        status_version = 1
        sessions = {}
        client_session = {}
        gi = GeoIP.open(geoip_data, GeoIP.GEOIP_STANDARD)

        for line in data.splitlines():

            if ',' in line:
                parts = line.split(',')
            else:
                parts = line.split('\t')

            if parts[0].startswith('GLOBAL'):
                break
            if parts[0] == 'HEADER':
                status_version = 3
                if parts[1] == 'CLIENT_LIST':
                    client_section = True
                    routes_section = False
                if parts[1] == 'ROUTING_TABLE':
                    client_section = False
                    routes_section = True
                continue
            if parts[0] == 'Updated':
                continue
            if parts[0] == 'Common Name':
                status_version = 1
                client_section = True
                routes_section = False
                continue
            if parts[0] == 'ROUTING TABLE' or parts[0] == 'Virtual Address':
                status_version = 1
                client_section = False
                routes_section = True
                continue
            if parts[0].startswith('>CLIENT'):
                continue

            session = {}
            if parts[0] == 'TUN/TAP read bytes':
                client_session['tuntap_read'] = int(parts[1])
                continue
            if parts[0] == 'TUN/TAP write bytes':
                client_session['tuntap_write'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP read bytes':
                client_session['tcpudp_read'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP write bytes':
                client_session['tcpudp_write'] = int(parts[1])
                continue
            if parts[0] == 'Auth read bytes':
                client_session['auth_read'] = int(parts[1])
                sessions['Client'] = client_session
                continue
            if client_section and not routes_section:
                if status_version == 1:
                    ident = parts[1]
                    sessions[ident] = session
                    session['username'] = parts[0]
                    remote_ip, port = parts[1].split(':')
                    session['bytes_recv'] = int(parts[2])
                    session['bytes_sent'] = int(parts[3])
                    # session['connected_since'] = get_date(parts[4])
                    session['connected_since'] = get_unix_time(get_date(parts[4]))
                elif status_version == 3:
                    local_ip = parts[3]
                    if local_ip:
                        ident = local_ip
                    else:
                        ident = str(uuid4())
                    sessions[ident] = session
                    if parts[8] != 'UNDEF':
                        session['username'] = parts[8]
                    else:
                        session['username'] = parts[1]
                    if parts[2].count(':') == 1:
                        remote_ip, port = parts[2].split(':')
                    else:
                        remote_ip = parts[2]
                        port = None
                    remote_ip_address = IPAddress(remote_ip)
                    # remote_ip_address = remote_ip
                    if local_ip:
                        # session['local_ip'] = IPAddress(local_ip)
                        session['local_ip'] = local_ip
                    else:
                        session['local_ip'] = ''
                    session['bytes_recv'] = int(parts[4])
                    session['bytes_sent'] = int(parts[5])
                    # session['connected_since'] = get_date(parts[7], uts=True)
                    session['connected_since'] = get_unix_time(get_date(parts[7], uts=True))
                    session['last_seen'] = session['connected_since']
                session['location'] = 'Unknown'
                if isinstance(remote_ip_address, IPv6Address) and remote_ip_address.ipv4_mapped is not None:
                    # noinspection PyUnboundLocalVariable
                    session['remote_ip'] = remote_ip_address.ipv4_mapped
                else:
                    # noinspection PyUnboundLocalVariable
                    session['remote_ip'] = remote_ip_address
                if port:
                    # noinspection PyUnboundLocalVariable
                    session['port'] = int(port)
                else:
                    session['port'] = ''
                if session['remote_ip'].is_private:
                    session['location'] = 'RFC1918'
                else:
                    try:
                        gir = gi.record_by_addr(str(session['remote_ip']))
                    except SystemError:
                        gir = None
                    if gir is not None:
                        session['location'] = gir['country_code']
                        session['city'] = get_str(gir['city'])
                        session['country_name'] = gir['country_name']
                        session['longitude'] = gir['longitude']
                        session['latitude'] = gir['latitude']
                session['remote_ip'] = remote_ip
            if routes_section and not client_section:
                if status_version == 1:
                    ident = parts[2]
                    # sessions[ident]['local_ip'] = IPAddress(parts[0])
                    sessions[ident]['local_ip'] = parts[0]
                    # sessions[ident]['last_seen'] = get_date(parts[3])
                    sessions[ident]['last_seen'] = get_unix_time(get_date(parts[3]))
                elif status_version == 3:
                    local_ip = parts[1]
                    if local_ip in sessions:
                        # sessions[local_ip]['last_seen'] = get_date(parts[5], uts=True)
                        sessions[local_ip]['last_seen'] = get_unix_time(get_date(parts[5], uts=True))

        if sessions:
            pretty_sessions = pformat(sessions)
            debug("=== begin sessions\n{0!s}\n=== end sessions".format(pretty_sessions))
        else:
            debug("no sessions")

        return sessions

    @staticmethod
    def parse_version(data):
        for line in data.splitlines():
            if line.startswith('OpenVPN'):
                return line.replace('OpenVPN Version: ', '')
