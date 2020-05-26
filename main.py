#!/usr/bin/env python3

import ipaddress
import json
import socket
import struct
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

    class FormatError(ValueError):
        pass

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
                missing_length = 8 - len(self.message[self.current_key])
                self.message[self.current_key] += line[:missing_length]
                if len(self.message[self.current_key]) == 8:
                    self.current_length = struct.unpack('<Q', self.message[self.current_key])[0]
                    self.current_read = 0
                    line = line[missing_length:]
                else:
                    return

            self.current_read += len(line)
            if self.current_read == self.current_length + 1:
                if not line.endswith(b'\n'):
                    raise SystemdMessageHandler.FormatError(
                        "Binary journald content not ended by \\n"
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
        # we populate the mandatory fields with sane defaults and hope for them to be overridden
        msg = {
            'version': '1.1',
            'short_message': 'missing',
            'host': self.client,
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
        class ClientError(Exception):
            def __init__(self, message, explain):
                super().__init__(message)
                self.explain = explain

        def do_POST(self):
            if self.path != '/upload':
                self.send_error(404)
                return

            if self.headers['Content-Type'] != 'application/vnd.fdo.journal':
                self.send_error(415)
                return

            self.send_response(100)
            self.send_response(200)
            self.end_headers()

            systemd_message_handler = SystemdMessageHandler(
                gelf_handler,
                self.client_address[0],
            )

            try:
                if self.headers['Transfer-Encoding'] == 'chunked':
                    while self.do_POST_chunk(systemd_message_handler):
                        pass
                else:
                    for line in self.rfile:
                        systemd_message_handler.handle_line(line)

            except (self.ClientError, SystemdMessageHandler.FormatError) as e:
                try:
                    self.send_error(
                        400,
                        str(e),
                        getattr(e, 'explain'),
                    )
                except BrokenPipeError:
                    # the client may have disconnected unexpectedly
                    pass

            except BrokenPipeError:
                # the client may have disconnected unexpectedly
                pass

        def do_POST_chunk(self, handler):
            chunk_length_line = self.rfile.readline()
            if not chunk_length_line:
                return False

            if not chunk_length_line.endswith(b'\r\n'):
                raise self.ClientError(
                    'Chunk Length Unterminated',
                    f'The chunk length line {repr(chunk_length_line)} was not '
                    'properly terminated by CRLF.',
                )

            chunk_length = int(chunk_length_line[:-2], 16)

            received = 0
            buf = b""

            for line in self.rfile:
                received += len(line)
                if received == chunk_length + 2:
                    if not line.endswith(b'\r\n'):
                        raise self.ClientError(
                            'Chunk Unterminated',
                            'The chunk was not properly terminated by CRLF.'
                        )

                    if chunk_length == 0:
                        self.send_response(202)
                        self.end_headers()
                        if len(buf) > 0:
                            self.log_message(
                                'Line buffer not empty at end of chunked transfer'
                            )
                        return
                    else:
                        buf = line[:-2]
                        break
                elif received > chunk_length + 2:
                    raise self.ClientError(
                        'Chunk Length Exceeded',
                        'The chunk was longer than specified initially '
                        f'(expected {chunk_length + 2} bytes, '
                        f'read {received} so far)'
                    )
                else:
                    try:
                        handler.handle_line(buf + line)
                    except SystemdMessageHandler.FormatError as e:
                        raise self.ClientError(
                            'Journal Format Error',
                            str(e),
                        )

                    buf = b""

            return True

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

    gelf_handler = graypy.GELFUDPHandler(args.graylog_host, args.graylog_port)
    server = ThreadedHTTPServer(
        (args.listen_host, args.listen_port),
        get_http_request_handler(gelf_handler),
    )
    server.serve_forever()
