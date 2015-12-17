#! /usr/bin/env python3

# TODO: Rekeying http://www.cisco.com/web/about/security/intelligence/securing-voip.html#12
# TODO: Standard configuration directory
# TODO: xdg

'''
A simple ffmpeg-based SRTP stream setup tool.

Doesn't have any ambitions of dealing with more complex matters such as
conferencing, NAT traversal, codec negotiation, etc—sane defaults and sane
environments only supported.
'''

# TODO: https://github.com/webrtc/samples
#       https://webrtchacks.com/chrome-extension/

from argparse import ArgumentParser
#from tempfile import NamedTemporaryFile
from base64 import b64encode
from socket import (socket, SOCK_STREAM, IPPROTO_TCP,
                    getaddrinfo, AI_ADDRCONFIG, AI_PASSIVE, AI_NUMERICHOST)
import subprocess
import logging
import json
import ssl


_DEFAULT_CODEC = 'opus'
_DEFAULT_TLS_CIPHERS = '!eNULL:!aNULL:kDHE+aRSA+HIGH'
_DEFAULT_SRTP_CIPHER = 'AES_CM_128_HMAC_SHA1_80'


def ssl_context_for(purpose, ca_certs, own_cert):
    ssl_context = ssl.create_default_context(purpose, cafile=ca_certs)
    #ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_context.load_cert_chain(own_cert)
    if ca_certs is None:
        ssl_context.load_default_certs(purpose)
    else:
        ssl_context.load_verify_locations(cafile=ca_certs)
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ##ssl_context.verify_flags |= ssl.VERIFY_X509_STRICT
    # Since we use only DH KEX later, we have to provide DH params. They aren't
    # automatically generated. There are no compiled in ones. If you don't do
    # this, you get weird "No shared cipher" errors at the client hello.
    if purpose == ssl.Purpose.CLIENT_AUTH:
        ssl_context.load_dh_params(args.dh_params)
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
            if len(chunk) == 0:
                break
        body, _, self.buffer = self.buffer.partition(b'\0')
        return json.loads(body.decode())

    def dump(self, payload):
        self.socket.sendall(self._frame_json(payload))

    @staticmethod
    def _frame_json(payload):
        return json.dumps(payload).encode() + b'\0'


def ffmpeg(*args, **kwargs):
    return  subprocess.Popen(['ffmpeg', '-loglevel', 'warning',
                                        '-nostdin'] +
                             list(args),
                              **kwargs)


def ffmpeg_in(speaker, sdp):
    #with NamedTemporaryFile(mode='w') as fp:
    #    fp.write(sdp)
    #    fp.seek(0)
    popen = ffmpeg('-f', 'sdp',
                   '-i', 'pipe:',
                   '-f', 'alsa',
                   speaker,
                   stdin=subprocess.PIPE,
                   universal_newlines=True)
    # Debug code
    #popen.terminate()
    #popen.wait()
    #popen = subprocess.Popen(['ffplay', '-f', 'sdp',
    #                                    '-i', 'pipe:'] +
    #                         (['showmode', '1'] if args.log_level == logging.DEBUG else []),
    #                         stdin=subprocess.PIPE,
    #                         universal_newlines=True)
    # Not .communicate(), which tries to read stdout, and does a wait().
    with popen.stdin:
        popen.stdin.write(sdp)
    return popen


def ffmpeg_out(microphone, address, srtp_params):
    return ffmpeg('-f', 'alsa',
                  '-i', microphone,
                  '-f', 'rtp',
                  '-c:a', _DEFAULT_CODEC,
                  *srtp_params,
                  'srtp://{}:{}'.format(*address))


def server(sk, address, ssl_context):
    sk.bind(address)
    sk.listen(1)
    logging.debug('Listening for one connection at a time')
    while True:
        connection, address = sk.accept()
        logging.debug('TCP connectionf from %s', address)
        ssl_socket = ssl_context.wrap_socket(connection, server_side=True)
        logging.debug('TLS handshake')
        with ssl_socket:
            json_socket = NullFramedJSONSocket(ssl_socket)
            payload = {}
            if args.public_address:
                payload['public_address'] = args.public_address
            srtp_key = ssl.RAND_bytes(30)
            srtp_params = gen_srtp_params(srtp_key)
            payload['audio_sdp'] = audio_sdp(*address, srtp_params=srtp_params)
            # TODO: Wait for application-layer message rather? For now, since
            #       the only thing we do is talk, nothing else, no point in
            #       waiting.
            json_socket.dump(payload)
            logging.debug('Sent %s', payload)
            response = json_socket.load()
            logging.debug('Got %s', response)

            inbound_media = ffmpeg_in(args.speaker, response['audio_sdp'])
            logging.debug('ffmpeg listening')
            json_socket.dump({'clear_to_send': True})
            logging.debug('Sent CTS')
            while not json_socket.load().get('clear_to_send', False):
                pass
            logging.debug('Got CTS')

            outbound_media = ffmpeg_out(args.microphone,
                                        response.get('public_address', address),
                                        srtp_params=srtp_params)
            logging.debug('ffmpeg sending')

            # TODO: Subprocess polling. Dirty trick with pipes?
            with inbound_media, outbound_media:
                pass
            logging.debug('Shutdown')


def client(sk, address, ssl_context):
    # TODO?
    ssl_context.check_hostname = True
    ssl_socket = ssl_context.wrap_socket(sk, server_hostname=args.name)
    ssl_socket.connect(address)

    with ssl_socket:
        json_socket = NullFramedJSONSocket(ssl_socket)
        payload = {}
        if args.public_address:
            payload['public_address'] = args.public_address
        srtp_key = ssl.RAND_bytes(30)
        srtp_params = gen_srtp_params(srtp_key)
        payload['audio_sdp'] = audio_sdp(*address, srtp_params=srtp_params)
        json_socket.dump(payload)
        logging.debug('Sent %s', payload)
        response = json_socket.load()
        logging.debug('Got %s', response)

        inbound_media = ffmpeg_in(args.speaker, response['audio_sdp'])
        logging.debug('ffmpeg listening')
        json_socket.dump({'clear_to_send': True})
        logging.debug('Sent CTS')
        while not json_socket.load().get('clear_to_send', False):
            pass
        logging.debug('Got CTS')

        outbound_media = ffmpeg_out(args.microphone,
                                    response.get('public_address', address),
                                    srtp_params=srtp_params)
        logging.debug('ffmpeg sending')

        # TODO: Subprocess polling. Dirty trick with pipes?
        with inbound_media, outbound_media:
            pass
        logging.debug('Shutdown')


def audio_sdp(host, port, srtp_params):
    # FIXME: Why does it say c=… 127.0.0.1? We're not originating from
    # localhost!
    popen = ffmpeg('-f', 'alsa',
                   '-i', args.microphone,
                   '-f', 'rtp',
                   '-t', '0',
                   '-c:a', _DEFAULT_CODEC,
                   *srtp_params,
                   'srtp://{}:{}'.format(host, port),
                   universal_newlines=True,
                   stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE)
    ffmpeg_stdout, ffmpeg_stderr = popen.communicate()
    popen.wait()
    if popen.returncode != 0:
        raise subprocess.SubprocessError(ffmpeg_stderr)
    return ffmpeg_stdout


# TODO: Use
def gen_srtp_params(srtp_key):
    # Doesn't seem like ffmpeg supports RFC 5764 (DTLS-SRTP), despite
    # supporting some of the ciphers, so we have to do the key negotiation
    # ourselves, so we just exchange the master key and master salt over a
    # TCP/TLS channel.
    return ['-srtp_out_suite', _DEFAULT_SRTP_CIPHER,
            '-srtp_out_params', b64encode(srtp_key)]


def argument_parser():
    ap = ArgumentParser()

    ap.add_argument('-q', action='store_const', const=logging.WARNING, dest='log_level')
    ap.add_argument('-D', action='store_const', const=logging.DEBUG, dest='log_level')

    ap.add_argument('-n', '--numeric', action='store_true', default=False)

    ap.add_argument('--cert', required=True)
    ap.add_argument('--certs')

    ap.add_argument('--microphone', default='default', help='arecord -L')
    ap.add_argument('--speaker', default='default', help='aplay -L')
    ap.add_argument('--webcam', default='/dev/video0', help='v4l2-ctl --list-devices')

    ap.add_argument('-p', '--public-address', nargs=2)

    sub_aps = ap.add_subparsers()

    client_ap = sub_aps.add_parser('client', aliases=['c'])
    # The extent to which we help you work around NAT
    client_ap.add_argument('name')
    client_ap.add_argument('host')
    client_ap.add_argument('port', type=int)
    client_ap.set_defaults(listen=False)

    server_ap = sub_aps.add_parser('server', aliases=['s'])
    server_ap.add_argument('--dh-params', required=True)
    # The extent to which we help you work around NAT
    server_ap.add_argument('host')
    server_ap.add_argument('port', type=int)
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
        raise SystemExit()

    flags = 0
    if args.listen:
        flags |= AI_ADDRCONFIG | AI_PASSIVE
    if args.numeric:
        flags |= AI_NMERICHOST
    family, type_, proto, _, address = \
            getaddrinfo(args.host, args.port,
                        type=SOCK_STREAM, proto=IPPROTO_TCP,
                        flags=flags)[0]
    sk = socket(family, type_, proto)

    if args.listen:
        mainloop = server
        purpose = ssl.Purpose.CLIENT_AUTH
    else:
        mainloop = client
        purpose = ssl.Purpose.SERVER_AUTH
    ssl_context = ssl_context_for(purpose,
                                  ca_certs=args.certs, own_cert=args.cert)
    with sk:
        mainloop(sk, address, ssl_context)
