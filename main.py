#!/usr/bin/env python3

import ipaddress
import json
import socket
import struct
import sys
import zlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

import graypy


class SystemdMessageHandler:
    facility_names = {
        0: "kern",
        1: "user",
        2: "mail",
        3: "daemon",
        4: "auth",
        5: "syslog",
        6: "lpr",
        7: "news",
        8: "uucp",
        9: "cron",
        10: "authpriv",
        16: "local0",
        17: "local1",
        18: "local2",
        19: "local3",
        20: "local4",
        21: "local5",
        22: "local6",
        23: "local7"
    }

    def __init__(self, gelf_handler, client):
        self.message = {}
        self.current_key = None
        self.current_length = None
        self.current_read = None
        self.gelf_handler = gelf_handler
        try:
            self.client = str(ipaddress.ip_address(client).ipv4_mapped or client)
        except AttributeError:
            self.client = client

    def handle_line(self, line):
        if self.current_key:
            if self.current_length is None:
                self.current_length = struct.unpack('<Q', line[:8])[0]
                self.current_read = 0
                line = line[8:]

            self.current_read += len(line)
            if self.current_read == self.current_length + 1:
                if not line.endswith(b'\n'):
                    print(
                        "Binary journald content not ended by \\n",
                        file=sys.stderr,
                    )

                self.message[self.current_key] += line[:-1]
                self.message[self.current_key] = self.message[self.current_key].decode(errors='backslashreplace')
                self.current_key = None
            else:
                self.message[self.current_key] += line

        elif b'=' in line:
            k, v = line[:-1].decode().split('=', 1)
            self.message[k] = v

        elif line == b'\n':
            self.finalize_message()
            self.message = {}

        else:
            self.current_key = line[:-1].decode()
            self.current_length = None
            self.message[self.current_key] = b""

    def finalize_message(self):
        msg = {
            'version': '1.0',
            '__real_remote_ip': self.client,
        }
        for key, value in self.message.items():
            if key == '__REALTIME_TIMESTAMP':
                msg['timestamp'] = float(value) / (1000 * 1000)
            elif key == 'PRIORITY':
                msg['level'] = int(value)
            elif key == 'SYSLOG_FACILITY':
                try:
                    msg['facility'] = self.facility_names.get(
                        int(value),
                        'unknown'
                    )
                except ValueError:
                    msg['facility'] = value
            elif key == '_HOSTNAME':
                msg['host'] = value
            elif key == 'MESSAGE':
                msg['short_message'] = value
            elif key.startswith('.'):
                continue
            elif key in ('__CURSOR', '__MONOTONIC_TIMESTAMP'):
                continue
            else:
                msg['_' + key] = value
        self.gelf_handler.send(zlib.compress(json.dumps(msg).encode()))


def get_http_request_handler(gelf_handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != '/upload':
                self.send_error(404)
                return

            if self.headers['Content-Type'] != 'application/vnd.fdo.journal':
                self.send_error(415)
                return

            chunked = self.headers['Transfer-Encoding'] == 'chunked'

            self.send_response(100)
            self.send_response(200)
            self.end_headers()

            buf = b""

            systemd_message_handler = SystemdMessageHandler(
                gelf_handler,
                self.client_address[0],
            )

            while True:
                if chunked:
                    chunk_length_line = self.rfile.readline()
                    if not chunk_length_line.endswith(b'\r\n'):
                        self.send_error(400)
                        return

                    chunk_length = int(chunk_length_line[:-2], 16)

                    received = 0

                for line in self.rfile:
                    if not chunked:
                        systemd_message_handler.handle_line(line)
                        continue

                    received += len(line)
                    if received == chunk_length + 2:
                        if not line.endswith(b'\r\n'):
                            self.send_error(
                                400,
                                'Bad Request',
                                'Chunk did not end with \\r\\n',
                            )
                            return

                        if chunk_length == 0:
                            self.send_response(202)
                            self.end_headers()
                            if len(buf) > 0:
                                self.log_message(
                                    "Line buffer not empty at end of chunked transfer"
                                )
                            return
                        else:
                            buf = line[:-2]
                            break
                    elif received > chunk_length + 2:
                        self.send_error(
                            400,
                            'Bad Request',
                            'Chunk longer than specified',
                        )
                        return
                    else:
                        systemd_message_handler.handle_line(buf + line)
                        buf = b""

        def log_request(code='-', size='-'):
            pass

    return Handler


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    address_family = socket.AF_INET6


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--graylog-host', default='localhost')
    parser.add_argument('--graylog-port', type=int, default=12201)
    parser.add_argument('--listen-host', default='::')
    parser.add_argument('--listen-port', type=int, default=8080)
    args = parser.parse_args()

    gelf_handler = graypy.GELFHandler(args.graylog_host, args.graylog_port)
    server = ThreadedHTTPServer(
        (args.listen_host, args.listen_port),
        get_http_request_handler(gelf_handler),
    )
    server.serve_forever()
