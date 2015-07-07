from OpenSSL import SSL
import simulation as xsim

def sim_session_resumption(sim, with_ticket = False, private_key = xsim.sample_key, cert = xsim.sample_cert):
    """Simulate SSL connections utilizing SSL session resumption feature.

       The first connection executes the full SSL handshake.  The second
       connection performs SSL session resumption via a session ID
       (default) or a session ticket (with_ticket=True), hence
       an abbreviated handshake.
    """

    client_ssl_ctx = SSL.Context(SSL.SSLv23_METHOD)
    server_ssl_ctx = SSL.Context(SSL.SSLv23_METHOD)
    server_ssl_ctx.use_privatekey(private_key)
    server_ssl_ctx.use_certificate(cert)
    client_ssl_ctx.set_cipher_list('AES256-SHA256')

    if with_ticket:
        server_ssl_ctx.set_session_cache_mode(SSL.SESS_CACHE_OFF)
        label = 'ssl_session_ticket'
    else:
        server_ssl_ctx.set_options(SSL.OP_NO_TICKET)
        label = 'ssl_session_id'

    c1, s1 = sim.ssl_connection(client_ssl_ctx, server_ssl_ctx)

    attrs = {}

    xsim.simple_ssl_conversation(
        c1,
        s1,
        xsim.http_conversation_with_label(label + '/create'),
        attrs).wait()

    c2, s2 = sim.ssl_connection(client_ssl_ctx, server_ssl_ctx)

    c2.set_session(attrs[xsim.SSL_SESSION_KEY])

    xsim.simple_ssl_conversation(
        c2,
        s2,
        xsim.http_conversation_with_label(label + '/resume')).wait()


if __name__ == '__main__':
    sim = xsim.Simulation('resume.pcap')
    sim_session_resumption(sim)
    sim_session_resumption(sim, with_ticket = True)

