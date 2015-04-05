#include "pcapgen.h"
#include <arpa/inet.h>

PcapGen::PcapGen()
    : pcap_(nullptr, pcap_close),
      pcap_dump_(nullptr, pcap_dump_close),
      lnet_(nullptr, libnet_destroy)
{
}


PcapGen::PcapGen(const std::string& path): PcapGen()
{
    pcap_.reset(pcap_open_dead(/*LINKTYPE_ETHERNET*/ 1, 65536));
    if (!pcap_)
        throw std::runtime_error("pcap_open_dead");
    pcap_dump_.reset(pcap_dump_open(pcap_.get(), path.c_str()));
    if (!pcap_dump_) {
        std::ostringstream ss;
        ss << "pcap_dump_open: " << pcap_geterr(pcap_.get());
        throw std::runtime_error(ss.str());
    }
    char errbuf[LIBNET_ERRBUF_SIZE];
    lnet_.reset(libnet_init(LIBNET_NONE, nullptr, errbuf));
    if (!lnet_) {
        std::ostringstream ss;
        ss << "libnet_init: " << errbuf;
        throw std::runtime_error("libnet_init");
    }
}


void PcapGen::send_tcp_packet(
        const TcpState& from, const TcpState& to,
        uint8_t control,
        const uint8_t* data, size_t size)
{
    if (!lnet_)
        return;

    libnet_build_tcp(from.port(),   // sp
                     to.port(),     // dp
                     from.seq(),    // seq
                     control & TH_ACK ? from.ack() : 0, // ack
                     control,       // control
                     from.win(),    // win
                     0,             // sum
                     0,             // urg
                     LIBNET_TCP_H + size,       // len
                     data,
                     (uint32_t)size,
                     lnet_.get(),
                     0);

    libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H + size, // ip_len
                      0,                          // tos
                      libnet_get_prand(LIBNET_PRu32), // id
                      0,                          // frag
                      64,                         // ttl
                      IPPROTO_TCP,
                      0,                          // sum
                      from.ip_addr(),             // src
                      to.ip_addr(),               // dst
                      0,
                      0,
                      lnet_.get(),
                      0);

    libnet_build_ethernet(from.mac_addr(),
                          to.mac_addr(),
                          ETHERTYPE_IP,
                          0,
                          0,
                          lnet_.get(),
                          0);

    // see libnet_write() source code; calling internal function here
    uint32_t packet_size;
    uint8_t *packet_data;
    auto c = libnet_pblock_coalesce(lnet_.get(), &packet_data, &packet_size);

    if (c == -1) {
        libnet_clear_packet(lnet_.get());
        return;
    }

    pcap_pkthdr packet_hdr;
    packet_hdr.ts.tv_sec = 0;
    packet_hdr.ts.tv_usec = 0;
    packet_hdr.len = packet_size;
    packet_hdr.caplen = packet_size;

    pcap_dump(reinterpret_cast<u_char *>(pcap_dump_.get()),
              &packet_hdr, packet_data);

    // see libnet_write() source code
    if (lnet_->aligner > 0) {
        packet_data -= lnet_->aligner;
    }

    free(packet_data);
    libnet_clear_packet(lnet_.get());
}


void PcapGen::perform_tcp_handshake(TcpState& client, TcpState& server)
{
    send_tcp_packet(client, server, TH_SYN, nullptr, 0);
    client.set_seq(client.seq() + 1);

    server.set_ack(client.seq());
    send_tcp_packet(server, client, TH_SYN | TH_ACK, 0, 0);
    server.set_seq(server.seq() + 1);

    client.set_ack(server.seq());
    send_tcp_packet(client, server, TH_ACK, 0, 0);
}


void PcapGen::perform_tcp_transmission(TcpState& from, TcpState& to, const uint8_t* data, size_t size)
{
    while (size != 0) {

        size_t fragment = std::min(size, size_t(1460));

        send_tcp_packet(from, to, TH_ACK, data, fragment);
        from.set_seq(from.seq() + uint32_t(fragment));

        to.set_ack(from.seq());
        send_tcp_packet(to, from, TH_ACK, nullptr, 0);

        size -= fragment;
        data += fragment;

    }
}


void PcapGen::perform_tcp_shutdown(TcpState& from, TcpState& to)
{
    send_tcp_packet(from, to, TH_FIN | TH_ACK, nullptr, 0);
    from.set_seq(from.seq() + 1);

    to.set_ack(from.seq());
    send_tcp_packet(to, from, TH_ACK, nullptr, 0);
}


void TcpSocket::send(const std::string& data)
{
    send(reinterpret_cast<const uint8_t*>(data.c_str()), data.size());
}


void TcpSocket::send(const uint8_t* data, size_t size)
{
    if (!conn_state_ || !pcap_gen_)
        return;

    pcap_gen_->perform_tcp_transmission(conn_state_->state[my_idx()],
                                        conn_state_->state[other_idx()],
                                        data,
                                        size);
}


void TcpSocket::close()
{
    if (!conn_state_ || !pcap_gen_)
        return;

    pcap_gen_->perform_tcp_shutdown(conn_state_->state[my_idx()],
                                    conn_state_->state[other_idx()]);

    conn_state_.reset();
    pcap_gen_.reset();
}


namespace {

TcpState parse_addr(const std::string& addr)
{
    auto copy = addr;

    do {

        auto pos = copy.find(':');
        if (pos == std::string::npos)
            break;
        copy[pos] = '\0';

        struct in_addr addr;
        if (inet_pton(AF_INET, copy.c_str(), &addr) != 1)
            break;

        long port;
        const char *port_str = copy.c_str() + pos + 1;
        char *bad;

        errno = 0;
        port = strtol(port_str, &bad, 10);
        if (bad == port_str || *bad || port <= 0 || port > 65535 || errno)
            break;

        return TcpState(addr.s_addr, port);

    } while (false);

    std::ostringstream os;
    os << "Invalid address: " << addr;
    throw std::runtime_error(os.str());
}

} // namespace {


std::pair<TcpSocket, TcpSocket>
PcapGen::create_connection(const std::string& client_addr,
                           const std::string& server_addr)
{
    auto state = std::make_shared<TcpConnectionState>();

    state->state[0] = parse_addr(client_addr);
    state->state[1] = parse_addr(server_addr);

    perform_tcp_handshake(state->state[0], state->state[1]);

    return std::make_pair(TcpSocket(shared_from_this(), state, 0),
                          TcpSocket(shared_from_this(), state, 1));
}


