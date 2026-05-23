#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

namespace netscope {

struct EthernetHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
} __attribute__((packed));

struct IPv4Header {
    uint8_t  version_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_frag_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t  data_offset_reserved;
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

enum class Protocol { UNKNOWN, TCP, UDP, ICMP, DNS, HTTP, HTTPS };

struct Packet {
    using Clock = std::chrono::steady_clock;
    std::string     src_ip;
    std::string     dst_ip;
    uint16_t        src_port{0};
    uint16_t        dst_port{0};
    Protocol        protocol{Protocol::UNKNOWN};
    std::string     flags;
    uint32_t        length{0};
    uint8_t         ttl{0};
    Clock::time_point timestamp;
    std::vector<uint8_t> payload;

    std::string protocol_str() const;
    std::string src_str() const;
    std::string dst_str() const;
};

} // namespace netscope
