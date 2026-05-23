#pragma once
#include "packet.h"
#include <optional>
#include <span>

namespace netscope {

/**
 * PacketParser - stateless, zero-copy packet decoder.
 *
 * Parses raw bytes into a structured Packet object using std::span
 * to avoid copies and support both live capture and PCAP replay.
 *
 * Design principles:
 *   - No dynamic allocation in the hot path
 *   - Returns std::optional so callers handle malformed frames cleanly
 *   - All header structs use __attribute__((packed)) + ntoh* conversions
 */
class PacketParser {
public:
    PacketParser() = default;
    std::optional<Packet> parse(std::span<const uint8_t> raw_frame) const;

private:
    std::optional<Packet> parse_ipv4(std::span<const uint8_t> ip_payload, Packet& pkt) const;
    void parse_tcp (std::span<const uint8_t> data, Packet& pkt) const;
    void parse_udp (std::span<const uint8_t> data, Packet& pkt) const;
    void parse_icmp(std::span<const uint8_t> data, Packet& pkt) const;

    static std::string ip_to_str(uint32_t ip_be);
    static std::string tcp_flags_str(uint8_t flags);
    static Protocol    infer_app_protocol(uint16_t src_port, uint16_t dst_port);
};

} // namespace netscope
