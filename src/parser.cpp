#include "parser.h"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>

namespace netscope {

std::optional<Packet> PacketParser::parse(std::span<const uint8_t> frame) const {
    if (frame.size() < sizeof(EthernetHeader)) return std::nullopt;
    const auto* eth = reinterpret_cast<const EthernetHeader*>(frame.data());
    const uint16_t etype = ntohs(eth->ether_type);
    Packet pkt;
    pkt.timestamp = Packet::Clock::now();
    pkt.length    = static_cast<uint32_t>(frame.size());
    if (etype == 0x0800)
        return parse_ipv4(frame.subspan(sizeof(EthernetHeader)), pkt);
    return pkt;
}

std::optional<Packet>
PacketParser::parse_ipv4(std::span<const uint8_t> data, Packet& pkt) const {
    if (data.size() < sizeof(IPv4Header)) return std::nullopt;
    const auto* iph = reinterpret_cast<const IPv4Header*>(data.data());
    const uint8_t ihl = (iph->version_ihl & 0x0F) * 4;
    if (data.size() < ihl) return std::nullopt;
    pkt.src_ip = ip_to_str(ntohl(iph->src_ip));
    pkt.dst_ip = ip_to_str(ntohl(iph->dst_ip));
    pkt.ttl    = iph->ttl;
    auto transport = data.subspan(ihl);
    switch (iph->protocol) {
        case 6:  parse_tcp (transport, pkt); break;
        case 17: parse_udp (transport, pkt); break;
        case 1:  parse_icmp(transport, pkt); break;
        default: pkt.protocol = Protocol::UNKNOWN;
    }
    return pkt;
}

void PacketParser::parse_tcp(std::span<const uint8_t> data, Packet& pkt) const {
    if (data.size() < sizeof(TCPHeader)) { pkt.protocol = Protocol::TCP; return; }
    const auto* tcph = reinterpret_cast<const TCPHeader*>(data.data());
    pkt.src_port = ntohs(tcph->src_port);
    pkt.dst_port = ntohs(tcph->dst_port);
    pkt.flags    = tcp_flags_str(tcph->flags);
    pkt.protocol = infer_app_protocol(pkt.src_port, pkt.dst_port);
    uint8_t doff = (tcph->data_offset_reserved >> 4) * 4;
    if (data.size() > doff) {
        auto payload = data.subspan(doff);
        pkt.payload.assign(payload.begin(), payload.end());
    }
}

void PacketParser::parse_udp(std::span<const uint8_t> data, Packet& pkt) const {
    if (data.size() < sizeof(UDPHeader)) { pkt.protocol = Protocol::UDP; return; }
    const auto* udph = reinterpret_cast<const UDPHeader*>(data.data());
    pkt.src_port = ntohs(udph->src_port);
    pkt.dst_port = ntohs(udph->dst_port);
    pkt.protocol = infer_app_protocol(pkt.src_port, pkt.dst_port);
    if (data.size() > sizeof(UDPHeader)) {
        auto payload = data.subspan(sizeof(UDPHeader));
        pkt.payload.assign(payload.begin(), payload.end());
    }
}

void PacketParser::parse_icmp(std::span<const uint8_t> data, Packet& pkt) const {
    pkt.protocol = Protocol::ICMP;
    if (!data.empty()) {
        uint8_t type = data[0];
        pkt.flags = (type == 8) ? "ECHO" : (type == 0 ? "ECHO_REPLY" : "OTHER");
    }
}

std::string PacketParser::ip_to_str(uint32_t ip_host) {
    char buf[INET_ADDRSTRLEN];
    uint32_t be = htonl(ip_host);
    inet_ntop(AF_INET, &be, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

std::string PacketParser::tcp_flags_str(uint8_t f) {
    std::string r;
    if (f & 0x02) r += "SYN+";
    if (f & 0x10) r += "ACK+";
    if (f & 0x01) r += "FIN+";
    if (f & 0x04) r += "RST+";
    if (f & 0x08) r += "PSH+";
    if (!r.empty()) r.pop_back();
    return r.empty() ? "NONE" : r;
}

Protocol PacketParser::infer_app_protocol(uint16_t src, uint16_t dst) {
    auto check = [](uint16_t p) -> Protocol {
        switch (p) {
            case 80:  return Protocol::HTTP;
            case 443: return Protocol::HTTPS;
            case 53:  return Protocol::DNS;
            default:  return Protocol::UNKNOWN;
        }
    };
    Protocol p = check(dst);
    return (p != Protocol::UNKNOWN) ? p : check(src);
}

std::string Packet::protocol_str() const {
    switch(protocol) {
        case Protocol::TCP:   return "TCP";
        case Protocol::UDP:   return "UDP";
        case Protocol::ICMP:  return "ICMP";
        case Protocol::DNS:   return "DNS";
        case Protocol::HTTP:  return "HTTP";
        case Protocol::HTTPS: return "HTTPS";
        default:              return "UNKNOWN";
    }
}
std::string Packet::src_str() const { return src_ip + ":" + std::to_string(src_port); }
std::string Packet::dst_str() const { return dst_ip + ":" + std::to_string(dst_port); }

} // namespace netscope
