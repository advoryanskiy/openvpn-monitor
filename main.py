from flask import Flask
from flask_sockets import Sockets
from monitor import ConfigLoader, OpenvpnMonitor

import gevent
import json
import subprocess
import re

app = Flask(__name__)
sockets = Sockets(app)

cfg = ConfigLoader('./openvpn-monitor.conf')

class IfstatMonitor(object):
    def __init__(self):
        self.input = 0.0
        self.output = 0.0
        self.p = re.compile('\d+\.\d+')

    @staticmethod
    def __iter_data():
        popen = subprocess.Popen(['ifstat', '-i', 'en1', '-b'], stdout=subprocess.PIPE, universal_newlines=True)
        for stdout_line in iter(popen.stdout.readline, b''):
            yield stdout_line

    def run(self):
        for data in self.__iter_data():
            res = self.p.findall(data)
            if len(res) == 2:
                self.input = float(res[0])
                self.output = float(res[1])

    def start(self):
        gevent.spawn(self.run)


ifstatMon = IfstatMonitor()
ifstatMon.start()


class MonitorBackend(object):
    def __init__(self):
        self.clients = list()

    @staticmethod
    def __iter_data():
        with OpenvpnMonitor(cfg) as ovpnmon:
            while True:
                ovpnmon.collect_data(ovpnmon.vpn)
                ovpnmon.vpn['stats']['kbpsIn'] = ifstatMon.input
                ovpnmon.vpn['stats']['kbpsOut'] = ifstatMon.output
                yield json.dumps(ovpnmon.vpn)

                gevent.sleep(1)

    def register(self, client):
        self.clients.append(client)

    # noinspection PyBroadException
    def send(self, client, data):
        try:
            client.send(data)
        except Exception:
            self.clients.remove(client)

    def run(self):
        for data in self.__iter_data():
            print('status: {0}'.format(data))
            for client in self.clients:
                gevent.spawn(self.send, client, data)

    def start(self):
        gevent.spawn(self.run)


monitor = MonitorBackend()
monitor.start()


@sockets.route('/monitor')
def monitor_socket(ws):
    monitor.register(ws)

    while not ws.closed:
        gevent.sleep(0.1)


if __name__ == '__main__':
    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    server = pywsgi.WSGIServer(('', 5000), app, handler_class=WebSocketHandler)
    print('Starting server')
    server.serve_forever()
