/**
 * Unit tests for PacketParser.
 * Build: g++ -std=c++23 -I../include ../src/parser.cpp test_parser.cpp -o test_parser
 */
#include "parser.h"
#include <cassert>
#include <iostream>
#include <vector>
#include <arpa/inet.h>

using namespace netscope;

static std::vector<uint8_t> make_tcp_frame(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port, uint8_t flags)
{
    std::vector<uint8_t> frame(sizeof(EthernetHeader)+sizeof(IPv4Header)+sizeof(TCPHeader), 0);
    auto* eth = reinterpret_cast<EthernetHeader*>(frame.data());
    eth->ether_type = htons(0x0800);
    auto* ip = reinterpret_cast<IPv4Header*>(frame.data()+sizeof(EthernetHeader));
    ip->version_ihl  = 0x45; ip->protocol = 6;
    ip->total_length = htons(frame.size()-sizeof(EthernetHeader));
    ip->src_ip = htonl(src_ip); ip->dst_ip = htonl(dst_ip); ip->ttl = 64;
    auto* tcp = reinterpret_cast<TCPHeader*>(frame.data()+sizeof(EthernetHeader)+sizeof(IPv4Header));
    tcp->src_port = htons(src_port); tcp->dst_port = htons(dst_port);
    tcp->data_offset_reserved = 0x50; tcp->flags = flags;
    return frame;
}

void test_syn_packet() {
    PacketParser p;
    auto frame = make_tcp_frame(0xC0A8010A, 0x0A000001, 54321, 80, 0x02);
    auto r = p.parse({frame.data(), frame.size()});
    assert(r.has_value());
    assert(r->src_ip == "192.168.1.10");
    assert(r->dst_ip == "10.0.0.1");
    assert(r->src_port == 54321);
    assert(r->dst_port == 80);
    assert(r->protocol == Protocol::HTTP);
    assert(r->flags == "SYN");
    std::cout << "[PASS] test_syn_packet\n";
}

void test_https_ack() {
    PacketParser p;
    auto frame = make_tcp_frame(0x01020304, 0x05060708, 443, 12345, 0x10);
    auto r = p.parse({frame.data(), frame.size()});
    assert(r.has_value());
    assert(r->protocol == Protocol::HTTPS);
    assert(r->flags == "ACK");
    std::cout << "[PASS] test_https_ack\n";
}

void test_malformed_short_frame() {
    PacketParser p;
    std::vector<uint8_t> tiny{0x00, 0x01, 0x02};
    auto r = p.parse({tiny.data(), tiny.size()});
    assert(!r.has_value());
    std::cout << "[PASS] test_malformed_short_frame\n";
}

void test_fin_rst_flags() {
    PacketParser p;
    auto frame = make_tcp_frame(0x01010101, 0x02020202, 1234, 5678, 0x05);
    auto r = p.parse({frame.data(), frame.size()});
    assert(r.has_value());
    assert(r->flags.find("FIN") != std::string::npos);
    assert(r->flags.find("RST") != std::string::npos);
    std::cout << "[PASS] test_fin_rst_flags\n";
}

int main() {
    std::cout << "Running PacketParser tests...\n\n";
    test_syn_packet(); test_https_ack();
    test_malformed_short_frame(); test_fin_rst_flags();
    std::cout << "\nAll 4 tests passed.\n";
}
