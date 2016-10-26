# -*- coding: utf-8 -*-
import brotli
import gzip
import httplib
import gc
import json
import os
import re
import select
import socket
import ssl
import sys
import threading
import time
import urlparse
import zlib

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from HTMLParser import HTMLParser
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from OpenSSL import SSL

from django.conf import settings
from proxy.models import RewriteRules
from .helper import format_header_keys


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


def generate_cert(hostname, cakey, cacert, certkey, certpath):
    """
    Generates a signed certificate with our root CA, issued for the given hostname, and stores it in "certpath".
    """
    if not os.path.isfile(certpath):
        epoch = "%d" % (time.time() * 1000)

        p1 = Popen(["openssl", "req", "-new", "-key", certkey, "-subj", "/CN={}".format(hostname)], stdout=PIPE)
        p2 = Popen(
            ["openssl", "x509", "-req", "-sha256", "-days", "36500", "-CA", cacert, "-CAkey", cakey,
             "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
        p2.communicate()


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # suppress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class SSLContext(object):
    """
    Simple mocked SSL connection to allow parsing of the ClientHello
    (source: https://gist.github.com/DonnchaC/4a89bf7c52500a1d7e7b)
    """

    def __init__(self):
        """
        Initialize an SSL connection object
        """
        self.server_name = None

        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_tlsext_servername_callback(self.get_servername)

        self.connection = SSL.Connection(context=context)
        self.connection.set_accept_state()

    def get_servername(self, connection):
        """
        Callback to retrieve the parsed SNI extension when it is parsed
        """
        self.server_name = connection.get_servername()

    def parse_client_hello(self, client_hello):
        try:
            # Write the SSL handshake into the BIO memory stream.
            self.connection.bio_write(client_hello)
            # Start parsing the client handshake from the memory stream
            self.connection.do_handshake()
        except SSL.Error:
            # We don't have a complete SSL handshake, only the ClientHello,
            # close the connection once we hit an error.
            self.connection.shutdown()

        # Should have run the get_servername callback already
        return self.server_name


class ThreadingHTTPSServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 10
    # match valid domain names, including its subdomain, (e.g. "www.google.com")
    domain_regex = re.compile("((?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+)(?:[A-Z0-9-]{2,63}(?<!-)))",
                              re.IGNORECASE)

    def get_request(self):
        request, client_address = self.socket.accept()

        context = SSLContext()
        data = request.recv(65536, socket.MSG_PEEK)
        hostname = context.parse_client_hello(data)

        # check if either the data or hostname is empty
        if data is None:
            request.close()
            return request, client_address
        elif hostname is None:
            # the ClientHello rarely fails to get a result, but if it does we instead use regex to
            # match the longest url in the encrypted https data
            match = self.domain_regex.findall(data)
            if not match:
                request.close()
                return request, client_address
            hostname = sorted(match, key=lambda x: len(x))[-1]

        certpath = os.path.join(self.certdir, hostname + '.crt')
        generate_cert(hostname, self.cakey, self.cacert, self.certkey, certpath)
        request = ssl.wrap_socket(request, keyfile=self.certkey, certfile=certpath, server_side=True)
        return request, client_address


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 0.75  # overridden attribute for the socket connection
    request_timeout = 10  # timeout for the request

    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # suppress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = os.path.join(self.certdir, hostname + '.crt')

        with self.lock:
            generate_cert(hostname, self.cakey, self.cacert, self.certkey, certpath)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1":
            self.close_connection = 0

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        if req.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))
        elif req_body_modified is False:
            self.send_error(403)
            return

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        req_headers = self.filter_headers(req.headers)

        intercepted_body = self.intercept_handler(req)
        if intercepted_body is not None:
            intercepted_body = intercepted_body.encode('utf-8')
            self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, ''))
            self.wfile.write('Content-Encoding: identity\r\n')
            self.wfile.write('Content-Length: {}\r\n'.format(str(len(intercepted_body))))
            self.wfile.write('Content-Type: charset=UTF-8\r\n')
            self.end_headers()
            self.wfile.write(intercepted_body)
            self.wfile.flush()
            return

        try:
            origin = (scheme, netloc)
            if origin not in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.request_timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.request_timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req_headers))
            res = conn.getresponse()
            res_body = res.read()
            conn.close()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
        res.headers = res.msg
        res.response_version = version_table[res.version]

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))
        elif res_body_modified is False:
            self.send_error(403)
            return

        res_headers = self.filter_headers(res.headers)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res_headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        # Uncomment below if you want to do something with the response
        # with self.lock:
        #     self.save_handler(req, req_body, res, res_body_plain)

    do_HEAD = do_GET
    do_POST = do_GET
    do_OPTIONS = do_GET
    do_DELETE = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        return headers

    def encode_content_body(self, text, encodings):
        encodings = [encoding.strip() for encoding in encodings.split(',')]
        for e in encodings:
            if ';' in e:
                encoding, q_val = e
            else:
                encoding = e
                q_val = '1'
            if encoding == 'identity':
                data = text
            elif encoding in ('gzip', 'x-gzip'):
                io = StringIO()
                with gzip.GzipFile(fileobj=io, mode='wb') as f:
                    f.write(text)
                data = io.getvalue()
            elif encoding == 'deflate':
                data = zlib.compress(text)
            elif encoding == 'br':
                data = brotli.compress(text)
            else:
                continue
            return data
        raise Exception("Unknown Content-Encoding: %s" % ','.join(encodings))

    def decode_content_body(self, data, encodings):
        encodings = [encoding.strip() for encoding in encodings.split(',')]
        for e in encodings:
            if ';' in e:
                encoding, q_val = e.split(';', maxsplit=1)
            else:
                encoding = e
                q_val = '1'
            if encoding == 'identity':
                text = data
            elif encoding in ('gzip', 'x-gzip'):
                io = StringIO(data)
                with gzip.GzipFile(fileobj=io) as f:
                    text = f.read()
            elif encoding == 'deflate':
                try:
                    text = zlib.decompress(data)
                except zlib.error:
                    text = zlib.decompress(data, -zlib.MAX_WBITS)
            elif encoding == 'br':
                text = brotli.decompress(data)
            else:
                continue
            return text
        raise Exception("Unknown Content-Encoding: %s" % ','.join(encodings))

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def _check_header_matches(self, header_name, header_value_regex, req_headers):
        """
        Checks whether a header pair from a request's headers matches the regex defined in the database with the same
        header key.

        :param header_name: the name of a header (str)
        :param header_value_regex: a regex string that will be matched to `req_headers`'s header value
        :param req_headers: a dict of {header names: header value}
        :return: whether the request header value matches the regex in the database
        """
        return header_name in req_headers and re.match(header_value_regex, req_headers[header_name])

    def intercept_handler(self, req):
        db_objs = RewriteRules.objects.values('url', 'headers', 'response')  # a dict
        db_matches = []  # will contain the tuples from `db_objs` that match the url regex
        for db_obj in db_objs:
            if re.match(db_obj['url'], req.path):
                db_matches.append(db_obj)
        # run the garbage collector since postgres doesn't seem to be closing connections
        gc.collect()
        if not db_matches:
            return
        # we treat our headers as case-insensitive and also replace hyphens with underscores
        req_headers = format_header_keys(dict(req.headers))
        for db_match in db_matches:
            # check if ALL request headers matches the regex in the database, then return the database response
            if all(self._check_header_matches(db_match_header, db_match['headers'][db_match_header], req_headers)
                   for db_match_header in db_match['headers']):
                # if the loop finishes without breaking, then all headers have matched and we return the response
                return db_match['response']

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        if settings.DEBUG:
            self.print_info(req, req_body, res, res_body)


def run_http(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    port = 80
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print('*' * 80)
    print("Serving HTTP Proxy on {} port {}...".format(sa[0], sa[1]))
    httpd.serve_forever()


def run_https(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPSServer, protocol="HTTP/1.1"):
    port = 443
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print('*' * 80)
    print("Serving HTTPS Proxy on {} port {}...".format(sa[0], sa[1]))
    httpd.serve_forever()


def run():
    http_thread = threading.Thread(target=run_http, args=[])
    https_thread = threading.Thread(target=run_https, args=[])
    http_thread.start()
    https_thread.start()
    http_thread.join()
    https_thread.join()
