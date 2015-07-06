import sys
import eventlet.semaphore
import eventlet.queue
import eventlet.greenthread
from OpenSSL import SSL
from OpenSSL import crypto
import pcapgen


def default_tx_hook(c, data, mem = {}):
    """Ssl_pipe helper (internals)"""
    sys.stdout.write('({}) {}\n'.format(mem.setdefault(c, len(mem)), repr(data)))


def bio_read_dummy():
    """Ssl_pipe helper (internals)"""
    raise SSL.WantReadError


def patch_ssl_connection(conn, queues, tx_hook):
    """Ssl_pipe helper (internals)"""
    rx_queue, tx_queue = queues
    rx_lock = eventlet.semaphore.Semaphore(1)
    tx_lock = eventlet.semaphore.Semaphore(1)
    bs = 4096

    def do_send_locked():
        try:
            while True:
                block = conn.bio_read(bs)
                tx_hook(conn, block)
                tx_queue.put(block)
        except SSL.WantReadError:
            pass

    def do_send():
        try:
            block = conn.bio_read(bs)
            bio_read = conn.bio_read
            conn.bio_read = bio_read_dummy
            with tx_lock:
                conn.bio_read = bio_read
                tx_queue.put(block)
                do_send_locked()
        except SSL.WantReadError:
            pass

    def do_recv():
        with rx_lock:
            if conn.want_read():
                block = rx_queue.get()
                conn.bio_write(block)

    def tx_wrap(bound_method):
        def wrapper(*args, **kv):
            with tx_lock:
                while True:
                    try:
                        res = bound_method(*args, **kv)
                        do_send_locked()
                        return res
                    except SSL.WantReadError:
                        do_send_locked()
                        do_recv()
                    except SSL.WantWriteError:
                        do_send_locked()
        return wrapper

    def rx_wrap(bound_method):
        def wrapper(*args, **kv):
            try:
                res = bound_method(*args, **kv)
                do_send()
                return res
            except SSL.WantReadError:
                do_send()
                do_recv()
            except SSL.WantWriteError:
                do_send()
        return wrapper

    conn.do_handshake = tx_wrap(conn.do_handshake)
    conn.recv         = rx_wrap(conn.recv)
    conn.renegotiate  = tx_wrap(conn.renegotiate)
    conn.send         = tx_wrap(conn.send)
    conn.sendall      = tx_wrap(conn.sendall)
    conn.shutdown     = tx_wrap(conn.shutdown)

    return conn


def ssl_pipe(c1, c2, tx_hook = default_tx_hook):
    """Stitches a pair of OpenSSL.SSL connection objects together; data
       sent on c1 can be received on c2 and vice versa.

       Ssl_pipe only establishes a transport; no SSL messages are
       exchanged yet.

       Connection objects are patched in such a way that blocking
       methods on c1 and c2 can be called provided that c1 and c2 are
       serviced in different green threads.
    """
    c1.set_connect_state()
    c2.set_accept_state()

    queues = eventlet.queue.Queue(), eventlet.queue.Queue()
    return (
        patch_ssl_connection(c1, queues, tx_hook),
        patch_ssl_connection(c2, (queues[1], queues[0]), tx_hook))


def simple_ssl_conversation(client, server, messages):
    """Performs a handshake and exchanges messages between a pair of
       OpenSSL.SSL connections finally performing a shutdown.

       Messages[0] originates from the client and messages[1] is the
       server response, etc.
    """
    driver_gt = None

    def conversation(conn, key):
        try:
            conn.do_handshake()
            for i, msg in enumerate(messages):
                if i % 2 == key:
                    conn.sendall(msg)
                else:
                    l = 0
                    while l != len(msg):
                        block = conn.recv(len(msg) - l)
                        if not block:
                            break
                        l += len(block)
            conn.shutdown()
        except:
            assert driver_gt
            driver_gt.kill(*sys.exc_info())
            raise

    spawn = eventlet.greenthread.spawn

    def driver():
        t1 = spawn(conversation, client, 0)
        t2 = spawn(conversation, server, 1)
        try:
            t1.wait()
            t2.wait()
        except:
            t1.cancel()
            t2.cancel()
            raise

    driver_gt = spawn(driver)
    return driver_gt


class Simulation(object):
    """The whole widget: """
    def __init__(self, output_pcap_path):
        """Init simulation; a pcap file is generated"""
        self._pcapgen = pcapgen.open(output_pcap_path)
    def ssl_connection(self, client, server):
        """Setup an SSL connection, all exchanged messages are saved in
           the pcap file.
        """
        client_ssl_ctx, client_addr = client
        server_ssl_ctx, server_addr = server

        client_socket, server_socket = self._pcapgen.create_connection(
            client_addr, server_addr)

        def tx_hook(ssl, data):
            if ssl == client_ssl:
                client_socket.send(data)
            elif ssl == server_ssl:
                server_socket.send(data)

        client_ssl, server_ssl = ssl_pipe(
            SSL.Connection(client_ssl_ctx),
            SSL.Connection(server_ssl_ctx),
            tx_hook)

        def wrap(bound_method, socket):
            def wrapper(*args, **kv):
                res = bound_method(*args, **kv)
                socket.close()
                return res
            return wrapper

        client_ssl.shutdown = wrap(client_ssl.shutdown, client_socket)
        server_ssl.shutdown = wrap(server_ssl.shutdown, server_socket)

        return client_ssl, server_ssl
        

sample_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
'''-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDIlow8hj3CsHb3FfmOGYMDFgeHbN7yGfX+X04PV0H1Wa+SW7aC
yzbSmLuhacBedXLr+FCR8FhsCeNwm+QEY9peHfSIco09KhREVh/SiDzSKm7U5Izm
54/hSYRrPUlnfMmtvZcgjKrsf3Ewhwm9aaagEkE7gmMPMnel276MgaJuHQIDAQAB
AoGALFfbuKWUka2hHw5klN1e8Re1omKXBr5me01mXE3V7v9cqOZNeqyh+fx5vj06
oaclOLU0Wo7ffULSXNqZlb7dTvxRag4Drf5Y9TGQitgbirtVoA8h1y3FZ9lGcqpk
EJktv8U07hnFPxPgM09t6mm/18bD0C/8I4G4dq7CNvj7S6ECQQD9LghReNusYg8Q
n6bKy9Gw+0/tk/dfv7L+t2/2piM9kIoQlX4jGVIa6Bt4cqagVlWMBn/+SdCayzkM
WhMNkU4/AkEAytKLcq70wCcwtBU53UaLTuVk7wXUQVXyqYp5Nh8LL9gml5QF853i
48VQt33lCL5h34ElwBl3LHQoQ9sdOzNkowJBAJ+aP0As8j6PanPOUTUSm9P3+YEJ
gC5qCIquVPSl8x1CWubtdqDlu26e14JstEHrau5kwpcpLUoHxqTUu6IX8b0CQC3c
i+Gjw/4LHo0p24q4X9m4LymJFOStLZC+mgft3xazdo6BzxK2Gc7NGCJVmktu2Syz
xDh6yaLIpS4qxqJTTacCQDPlhYatK48uSv/YmuagWNf3RuwKeR8hYHln+wHtzfK1
g2ZHdCgQX5a4Zl2ZYKYJOKYYJJ1pXdwS25tAGdgjCdU=
-----END RSA PRIVATE KEY-----''')


sample_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
'''-----BEGIN CERTIFICATE-----
MIICLTCCAZYCCQCeYtUzppjV/TANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJy
dTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRQwEgYDVQQDEwtleGFtcGxlLm9yZzAeFw0xNDA5MTcxMjI3MDZa
Fw0xNTA5MTcxMjI3MDZaMFsxCzAJBgNVBAYTAnJ1MRMwEQYDVQQIEwpTb21lLVN0
YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFDASBgNVBAMT
C2V4YW1wbGUub3JnMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIlow8hj3C
sHb3FfmOGYMDFgeHbN7yGfX+X04PV0H1Wa+SW7aCyzbSmLuhacBedXLr+FCR8Fhs
CeNwm+QEY9peHfSIco09KhREVh/SiDzSKm7U5Izm54/hSYRrPUlnfMmtvZcgjKrs
f3Ewhwm9aaagEkE7gmMPMnel276MgaJuHQIDAQABMA0GCSqGSIb3DQEBBQUAA4GB
AH+0eeW7lDsXXiChBz3OrMVomTvIdjFvmTqjUpsOBtgPrZwrlUXnuqAkLaOx52xv
V4+QGpLb/hZMplNwZhBs5bcHzVJ81eKHe5OmqEOky4k21ISukFU+tqm5cQ+8ifGt
4LJDGnqdSKYrNX8HbLhwP9sg+fRfvvn+EKtE7DA0Svpf
-----END CERTIFICATE-----''')


if __name__ == '__main__':

    import traceback
    import itertools
    from pprint import pprint

    import eventlet.debug
    eventlet.debug.hub_exceptions(False)

    # only suites using RSA-based key exchange listed;
    # there is some overlap between suites, that's fine since different
    # SSL/TLS versions apply cryptography differently

    ssl_v3_0_suites = [
        'NULL-MD5',
        'NULL-SHA',
        'EXP-RC4-MD5',
        'RC4-MD5',
        'RC4-SHA',
        'EXP-RC2-CBC-MD5',
        'IDEA-CBC-SHA',
        'EXP-DES-CBC-SHA',
        'DES-CBC-SHA',
        'DES-CBC3-SHA'
    ]

    tls_v1_0_suites = [
        'NULL-MD5',
        'NULL-SHA',
        'EXP-RC4-MD5',
        'RC4-MD5',
        'RC4-SHA',
        'EXP-RC2-CBC-MD5',
        'IDEA-CBC-SHA',
        'EXP-DES-CBC-SHA',
        'DES-CBC-SHA',
        'DES-CBC3-SHA',
        'AES128-SHA',
        'AES256-SHA',
    ]

    tls_v1_1_suites = tls_v1_0_suites

    tls_v1_2_suites = [
        'NULL-SHA256',
        'AES128-SHA256',
        'AES256-SHA256',
        'AES128-GCM-SHA256',
        'AES256-GCM-SHA384'
    ]

    def all_opts_but(opt):
        assert opt
        s = set((
            SSL.OP_NO_SSLv2,
            SSL.OP_NO_SSLv3,
            SSL.OP_NO_TLSv1,
            SSL.OP_NO_TLSv1_1,
            SSL.OP_NO_TLSv1_2))
        s.difference_update((opt,))
        return s

    all_regimens = [
        ('SSL3.0', all_opts_but(SSL.OP_NO_SSLv3), ssl_v3_0_suites),
        ('TLS1.0', all_opts_but(SSL.OP_NO_TLSv1), tls_v1_0_suites),
        ('TLS1.1', all_opts_but(SSL.OP_NO_TLSv1_1), tls_v1_1_suites),
        ('TLS1.2', all_opts_but(SSL.OP_NO_TLSv1_2), tls_v1_2_suites),
    ]

    all_regimens_flat = list(
        itertools.chain(
            *(itertools.izip(itertools.cycle((ver,)), itertools.cycle((opts,)), suites)
                for ver,opts,suites in all_regimens)))
    
    sim = Simulation('simulation.pcap')

    for i,(ver,opts,suite) in enumerate(all_regimens_flat):
        id_str = '{}/{}'.format(ver, suite)

        try:
            client_ssl_ctx = SSL.Context(SSL.SSLv23_METHOD)
            server_ssl_ctx = SSL.Context(SSL.SSLv23_METHOD)
            server_ssl_ctx.use_privatekey(sample_key)
            server_ssl_ctx.use_certificate(sample_cert)

            server_ssl_ctx.set_cipher_list('ALL,COMPLEMENTOFALL,EXPORT')
            client_ssl_ctx.set_cipher_list(suite)

            for opt in opts:
                client_ssl_ctx.set_options(opt)

            client, server = sim.ssl_connection(
                (client_ssl_ctx, '10.0.10.103:{}'.format(9999+i)),
                (server_ssl_ctx, '10.0.10.1:443'))

            simple_ssl_conversation(client, server, [
                'GET /{} HTTP/1.1\r\nHost: example.org\r\n\r\n'.format(id_str),
                'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n']).wait()
 
            print id_str

        except Exception as e:
            sys.stderr.write(id_str + ': ' + ''.join(traceback.format_exception_only(type(e), e)))

