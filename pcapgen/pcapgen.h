#include <memory>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <pcap/pcap.h>
#include <libnet.h>


class TcpState;
class TcpSocket;


class PcapGen: public std::enable_shared_from_this<PcapGen>
{
    PcapGen(const PcapGen&) = delete;
    void operator = (const PcapGen&) = delete;
public:
    PcapGen();
    PcapGen(const std::string& path);
    void close() { pcap_.reset(); pcap_dump_.reset(); lnet_.reset(); }

    void send_tcp_packet(
        const TcpState& from, const TcpState& to,
        uint8_t control,
        const uint8_t* data = nullptr, size_t size = 0);

    void perform_tcp_handshake(TcpState&, TcpState&);
    void perform_tcp_transmission(TcpState&, TcpState&, const uint8_t*, size_t);
    void perform_tcp_shutdown(TcpState&, TcpState&);

    std::pair<TcpSocket, TcpSocket>
    create_connection(const std::string& client_addr,
                      const std::string& server_addr);


private:
    std::unique_ptr<pcap_t, decltype(&pcap_close)>              pcap_;
    std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>  pcap_dump_;
    std::unique_ptr<libnet_t, decltype(&libnet_destroy)>        lnet_;
};


inline std::shared_ptr<PcapGen> open(const std::string& path)
{
    return std::make_shared<PcapGen>(path);
}


class TcpState
{
public:
    TcpState()
    {
    }

    TcpState(uint32_t ip_addr, uint16_t port)
        : mac_addr_{0, 0, 0, 0, 0, 0}, ip_addr_(ip_addr), port_(port),
          seq_(libnet_get_prand(LIBNET_PRu32)), ack_(0), win_(32767)
    {
    }

    const uint8_t* mac_addr() const { return mac_addr_; }
    uint32_t ip_addr() const { return ip_addr_; }
    uint16_t port() const { return port_; }
    uint32_t seq() const { return seq_; }
    uint32_t ack() const { return ack_; }
    uint32_t win() const { return win_; }

    void set_mac_addr(const uint8_t* mac_addr)
    {
        memcpy(mac_addr_, mac_addr, sizeof mac_addr_);
    }
    void set_ip_addr(uint32_t ip_addr) { ip_addr_ = ip_addr; }
    void set_port(uint16_t port) { port_ = port; }
    void set_seq(uint32_t seq) { seq_ = seq; }
    void set_ack(uint32_t ack) { ack_ = ack; }
    void set_win(uint32_t win) { win_ = win; }

private:
    uint8_t mac_addr_[6];
    uint32_t ip_addr_;
    int16_t port_;
    uint32_t seq_;
    uint32_t ack_;
    uint32_t win_;
};


struct TcpConnectionState
{
    TcpState state[2];
};


class TcpSocket
{
public:
    TcpSocket(): socket_idx_(0) {}
    TcpSocket(const std::shared_ptr<PcapGen>& pcap_gen,
              const std::shared_ptr<TcpConnectionState>& conn_state,
              int socket_idx)
        : pcap_gen_(pcap_gen),
          conn_state_(conn_state),
          socket_idx_(socket_idx)
    {
    }
    void send(const uint8_t*, size_t);
    void send(const std::string&);
    void close();
private:
    std::shared_ptr<PcapGen>                pcap_gen_;
    std::shared_ptr<TcpConnectionState>     conn_state_;
    int                                     socket_idx_;

    int my_idx() const { return socket_idx_ & 1; }
    int other_idx() const { return (~socket_idx_) & 1; }
};

