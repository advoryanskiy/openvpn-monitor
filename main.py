from flask import Flask
from flask_sockets import Sockets
from monitor import ConfigLoader, OpenvpnMonitor

import gevent
import json

app = Flask(__name__)
sockets = Sockets(app)

cfg = ConfigLoader('./openvpn-monitor.conf')


class MonitorBackend(object):
    def __init__(self):
        self.clients = list()

    @staticmethod
    def __iter_data():
        with OpenvpnMonitor(cfg) as ovpnmon:
            while True:
                ovpnmon.collect_data(ovpnmon.vpn)
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
