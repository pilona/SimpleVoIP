#! /usr/bin/env python3

# TODO: Standard configuration directory
# TODO: xdg
# TODO: Registrar
# TODO: SSH-like features: known_hosts, host configs

'''
A simple ffmpeg-based SRTP stream setup tool.

Doesn't have any ambitions of dealing with more complex matters such as
conferencing, NAT traversal, codec negotiation, etc—sane defaults and sane
environments only supported.
'''

# TODO: https://github.com/webrtc/samples
#       https://webrtchacks.com/chrome-extension/

from functools import partial
from argparse import ArgumentParser
from base64 import b64encode
from socket import (socket, AF_INET6, SOCK_STREAM, IPPROTO_TCP,
                    getaddrinfo, AI_PASSIVE)
from pprint import pformat
from sys import platform, exit
import subprocess
import logging
import json
import ssl


_DEFAULT_DEVICE = {'linux': 'alsa',
                   'darwin': 'avfoundation',
                   'win32': 'dshow',
                   'cygwin': 'dshow'}[platform]
_DEFAULT_CODEC, *_DEFAULT_CODEC_PARAMS = 'opus', '-application', 'voip'
_DEFAULT_PORT = 20000
_DEFAULT_TLS_CIPHERS = '!eNULL:!aNULL:kDHE+aRSA+HIGH'
_DEFAULT_SRTP_CIPHER = 'AES_CM_128_HMAC_SHA1_80'


def ssl_context_for(purpose, ca_certs, own_cert, dh_params=None):
    ssl_context = ssl.create_default_context(purpose, cafile=ca_certs)
    ssl_context.load_cert_chain(own_cert)
    if ca_certs is None:
        ssl_context.load_default_certs(purpose)
    else:
        ssl_context.load_verify_locations(cafile=ca_certs)
    # Force client cert requirement too
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ##ssl_context.verify_flags |= ssl.VERIFY_X509_STRICT
    # Since we use only DH KEX later, we have to provide DH params. They aren't
    # automatically generated. There are no compiled in ones. If you don't do
    # this, you get weird "No shared cipher" errors at the client hello.
    if purpose == ssl.Purpose.CLIENT_AUTH:
        ssl_context.load_dh_params(dh_params)
    # Enforce encryption and authentication.
    # Enforce perfect forward secrecy—only provided by Diffie-Hellman ephemeral
    # so far.
    # Enforce RSA-based authentication because of better failure modes.
    # Enforce 'high'—higher security suites.
    # See http://security.stackexchange.com/questions/5096/rsa-vs-dsa-for-ssh-authentication-keys/46781#46781.
    # TODO: Figure out how to enforce *generically*, better hash suites, and
    # not have outdated, slow, and known weaker ciphers like 3DES.
    ssl_context.set_ciphers(_DEFAULT_TLS_CIPHERS)
    ssl_context.set_alpn_protocols(['simplevoip/0'])

    return ssl_context


class NullFramedJSONSocket:
    '"socket"'

    def __init__(self, socket):
        self.socket = socket
        # Not the most efficient, but who cares here? It's a bloody control
        # channel, with small payoads.
        self.buffer = bytearray()

    def load(self):
        while self.buffer.rfind(b'\0') == -1:
            chunk = self.socket.recv(128)
            self.buffer += chunk
            # TODO: What does this really mean?
            if len(chunk) == 0:
                break
        body, _, self.buffer = self.buffer.partition(b'\0')
        return json.loads(body.decode())

    def dump(self, payload):
        self.socket.sendall(self._frame_json(payload))

    @staticmethod
    def _frame_json(payload):
        return json.dumps(payload).encode() + b'\0'


# Honestly, I'm only doing classes rather than functions like I used to because
# I need an excuse to use PascalCase, to make variable naming easier.
class FFmpeg(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        super().__init__(['ffmpeg', '-loglevel', 'warning',
                                    '-nostdin'] +
                         list(args),
                         **kwargs)


class FFmpegSink(FFmpeg):
    def __init__(self, device, speaker, sdp):
        super().__init__('-f', 'sdp', '-i', 'pipe:',
                         '-f', device, speaker,
                         stdin=subprocess.PIPE,
                         universal_newlines=True)
        # Not .communicate(), which tries to read stdout, and does a wait().
        with self.stdin:
            self.stdin.write(sdp)


class FFmpegSource(FFmpeg):
    def __init__(self, device, microphone, address, srtp_params):
        super().__init__('-f', device,
                         '-i', microphone,
                         '-f', 'rtp',
                         '-c:a', _DEFAULT_CODEC,
                         *_DEFAULT_CODEC_PARAMS,
                         *srtp_params,
                         'srtp://[{}]:{}'.format(*address))


class VoIPContext:
    @classmethod
    def from_namespace(cls, namespace):
        new = cls()

        new.listen = namespace.listen
        if new.listen:
            new.port = namespace.port
            dh_params = namespace.dh_params
        else:
            dh_params = None

        new.public_address = namespace.public_address

        new.device = namespace.device
        new.microphone = namespace.microphone
        new.speaker = namespace.speaker

        new.ssl_context_for = partial(ssl_context_for,
                                      ca_certs=namespace.certs,
                                      own_cert=namespace.cert,
                                      dh_params=dh_params)

        return new

    def serve(self):
        # TODO: getaddrinfo prefer dual stack if available, for
        # local bind address
        family, type_, proto, _, address = \
                getaddrinfo(None, self.port,
                            family=AF_INET6, proto=IPPROTO_TCP,
                            flags=AI_PASSIVE)[0]
        # Unlike SIP, or other running over a connectionless protocol, we don't
        # have the luxury of reusing the same port, so the calling and the
        # contact address aren't the same. Oh well. So people's phonebooks
        # shouldn't rely on peername()s collected from incoming calls.
        listen_socket = socket(family, type_, proto)
        listen_socket.bind(address)
        listen_socket.listen(1)
        return VoIPServer(listen_socket,
                          voip_context=self)

    def call(self, common_name, address):
        return VoIPClient(common_name, address,
                          voip_context=self)

class VoIPServer:
    def __init__(self, listen_socket, voip_context):
        self._listen_socket = listen_socket
        self._ssl_context = voip_context.ssl_context_for(ssl.Purpose.CLIENT_AUTH)
        self._voip_context = voip_context

    def accept(self):
        connection, address = self._listen_socket.accept()
        logging.debug('TCP connection from %s.', address)
        ssl_socket = self._ssl_context.wrap_socket(connection, server_side=True)
        logging.debug('TLS handshake')

        return VoIPCall(ssl_socket, self._voip_context)

    def run(self):
        while True:
            voip_call = self.accept()
            voip_call.accept()
            voip_call.wait()


class VoIPClient:
    def __init__(self, common_name, address, voip_context):
        self._common_name = common_name
        self._address = address
        self._voip_context = voip_context

    def connect(self):
        family, type_, proto, _, address = \
                getaddrinfo(*self._address,
                            family=AF_INET6, proto=IPPROTO_TCP)[0]
        connect_socket = socket(family, type_, proto)
        ssl_context = voip_context.ssl_context_for(ssl.Purpose.SERVER_AUTH)
        ssl_context.check_hostname = True
        ssl_socket = ssl_context.wrap_socket(connect_socket,
                                             server_hostname=self._common_name)
        ssl_socket.connect(address)
        logging.info('Calling %s@%s:%s.', ssl_socket.server_hostname, address)
        return VoIPCall(ssl_socket, self._voip_context)


class CallFailedError(RuntimeError):
    pass


class VoIPCall:
    def __init__(self, ssl_socket, voip_context):
        self._voip_context = voip_context
        self._ssl_socket = ssl_socket
        self._json_socket = NullFramedJSONSocket(ssl_socket)

    def accept(self):
        logging.info('Call from:\n%s',
                     pformat(self._ssl_socket.getpeercert()['subject']))
        self._json_socket.dump({'accept': True})
        self._run()

    def connect(self):
        if not self._json_socket.load()['accept'] is True:
            raise CallFailedError('rejected')
        self._run()

    def _gen_srtp_params(self):
        srtp_key = ssl.RAND_bytes(30)

        # Doesn't seem like ffmpeg supports RFC 5764 (DTLS-SRTP), despite
        # supporting some of the ciphers, so we have to do the key negotiation
        # ourselves, so we just exchange the master key and master salt over a
        # TCP/TLS channel.
        return ['-srtp_out_suite', _DEFAULT_SRTP_CIPHER,
                '-srtp_out_params', b64encode(srtp_key)]

    def _audio_sdp(self, host, port, srtp_params):
        # FIXME: Why does it say c=… 127.0.0.1? We're not originating from
        # localhost!
        ffmpeg = FFmpeg('-f', self._voip_context.device,
                        '-i', 'null',
                        '-f', 'rtp',
                        '-t', '0',
                        '-c:a', _DEFAULT_CODEC,
                        *srtp_params,
                        'srtp://[{}]:{}'.format(host, port),
                        universal_newlines=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
        ffmpeg_stdout, ffmpeg_stderr = ffmpeg.communicate()
        ffmpeg.wait()
        if ffmpeg.returncode != 0:
            raise subprocess.SubprocessError(ffmpeg_stderr)
        return ffmpeg_stdout

    def _send_sdp(self, srtp_params):
        payload = {}
        if self._voip_context.public_address:
            payload['public_address'] = self._voip_context.public_address
        # Don't care about IPv6 flow info nor scope id
        payload['audio_sdp'] = self._audio_sdp(*self._ssl_socket.getpeername()[:2],
                                               srtp_params=srtp_params)
        self._json_socket.dump(payload)
        logging.debug('Sent %s.', payload)

    def _recv_sdp(self):
        response = self._json_socket.load()
        logging.debug('Got %s.', response)
        return response['audio_sdp'], response.get('public_address', None)

    def _setup_inbound_media(self, audio_sdp):
        inbound_media = FFmpegSink(self._voip_context.device,
                                   self._voip_context.speaker,
                                   audio_sdp)
        logging.debug('ffmpeg listening.')
        self._json_socket.dump({'clear_to_send': True})
        logging.debug('Sent CTS.')
        assert self._json_socket.load()['clear_to_send'] is True
        logging.debug('Got CTS.')
        return inbound_media

    def _setup_outbound_media(self, address, srtp_params):
        outbound_media = FFmpegSource(self._voip_context.device,
                                      self._voip_context.microphone,
                                      address,
                                      srtp_params)
        logging.debug('ffmpeg sending.')
        return outbound_media

    def _run(self):
        srtp_params = self._gen_srtp_params()
        self._send_sdp(srtp_params)
        audio_sdp, public_address = self._recv_sdp()
        address = public_address or self._ssl_socket.getpeername()
        self._inbound_media = self._setup_inbound_media(audio_sdp)
        self._outbound_media = self._setup_outbound_media(address, srtp_params)

    def wait(self):
        with self._inbound_media, self._outbound_media:
            try:
                assert self._json_socket.load()['hangup'] is True
            except KeyboardInterrupt:
                pass
            self._inbound_media.terminate()
            self._outbound_media.terminate()
        logging.debug('Call shutdown.')
        self._json_socket.dump({'hangup': True})


def argument_parser():
    ap = ArgumentParser()

    ap.add_argument('-q', action='store_const',
                    const=logging.WARNING, dest='log_level',
                    help='quiet')
    ap.add_argument('-D', action='store_const',
                    const=logging.DEBUG, dest='log_level',
                    help='debug')

    ap.add_argument('--cert', required=True, help='client/server cert')
    ap.add_argument('--certs', help='CA certs')

    ap.add_argument('--device', default=_DEFAULT_DEVICE, help='ffmpeg -devices')
    ap.add_argument('--microphone', default='default', help='ffmpeg -sources')
    ap.add_argument('--speaker', default='default', help='ffmpeg -sinks')
    ap.add_argument('--webcam', default='/dev/video0', help='ffmpeg -sources')

    ap.add_argument('-p', '--public-address', nargs=2,
                    metavar=('HOST', 'PORT'))

    sub_aps = ap.add_subparsers()
    client_ap = sub_aps.add_parser('client', aliases=['c'])
    # The extent to which we help you work around NAT
    client_ap.add_argument('name')
    client_ap.add_argument('host')
    client_ap.add_argument('port', type=int)
    client_ap.set_defaults(listen=False)

    server_ap = sub_aps.add_parser('server', aliases=['s'])
    server_ap.add_argument('--dh-params', required=True)
    server_ap.add_argument('port', type=int, default=_DEFAULT_PORT, nargs='?')
    server_ap.set_defaults(listen=True)

    init_ap = sub_aps.add_parser('init')
    init_ap.add_argument('--dh-params', required=True)
    init_ap.set_defaults(init=True)

    return ap


if __name__ == '__main__':
    ap = argument_parser()
    args = ap.parse_args()

    if args.log_level is not None:
        logging.basicConfig(level=args.log_level)

    if getattr(args, 'init', False):
        subprocess.check_call(['openssl', 'req', '-new',
                                                 '-x509',
                                                 '-days', '365',
                                                 '-nodes',
                                                 '-out', args.cert,
                                                 '-keyout', args.cert])
        subprocess.check_call(['openssl', 'dhparam', '-out', args.dh_params,
                                                     '2048'])
        exit()

    voip_context = VoIPContext.from_namespace(args)
    if args.listen:
        voip_server = voip_context.serve()
        voip_server.run()
    else:
        voip_client = voip_context.call(args.name, (args.host, args.port))
        voip_call = voip_client.connect()
        voip_call.connect()
        voip_call.wait()
