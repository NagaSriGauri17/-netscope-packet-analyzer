/**
 * Unit tests for TrafficAnalyzer.
 * Build: g++ -std=c++23 -I../include ../src/analyzer.cpp test_analyzer.cpp -o test_analyzer
 */
#include "analyzer.h"
#include <cassert>
#include <iostream>
#include <thread>
#include <atomic>

using namespace netscope;

Packet make_pkt(const std::string& src, const std::string& dst,
                Protocol proto, const std::string& flags = "ACK",
                uint16_t sp = 1024, uint16_t dp = 80, uint32_t len = 200) {
    Packet p;
    p.src_ip = src; p.dst_ip = dst;
    p.src_port = sp; p.dst_port = dp;
    p.protocol = proto; p.flags = flags;
    p.length = len; p.ttl = 64;
    p.timestamp = Packet::Clock::now();
    return p;
}

void test_flow_stats() {
    TrafficAnalyzer a;
    for (int i = 0; i < 10; ++i)
        a.ingest(make_pkt("1.2.3.4","5.6.7.8",Protocol::TCP));
    assert(a.total_packets() == 10);
    assert(a.total_bytes()   == 2000);
    assert(!a.get_flow_stats().empty());
    std::cout << "[PASS] test_flow_stats\n";
}

void test_port_scan_detection() {
    std::atomic<int> fired{0};
    TrafficAnalyzer a([&](const Anomaly& an) {
        if (an.description.find("Port scan") != std::string::npos) ++fired;
    });
    for (uint16_t port = 1; port <= 25; ++port)
        a.ingest(make_pkt("9.9.9.9","10.0.0.1",Protocol::TCP,"SYN",50000,port,60));
    assert(fired.load() > 0);
    std::cout << "[PASS] test_port_scan_detection\n";
}

void test_thread_safety() {
    TrafficAnalyzer a;
    constexpr int N = 1000;
    auto worker = [&]() {
        for (int i = 0; i < N; ++i)
            a.ingest(make_pkt("1.1.1.1","2.2.2.2",Protocol::UDP));
    };
    std::thread t1(worker), t2(worker);
    t1.join(); t2.join();
    assert(a.total_packets() == 2*N);
    std::cout << "[PASS] test_thread_safety\n";
}

void test_reset() {
    TrafficAnalyzer a;
    a.ingest(make_pkt("1.2.3.4","5.6.7.8",Protocol::TCP));
    a.reset();
    assert(a.total_packets() == 0);
    assert(a.get_flow_stats().empty());
    std::cout << "[PASS] test_reset\n";
}

int main() {
    std::cout << "Running TrafficAnalyzer tests...\n\n";
    test_flow_stats(); test_port_scan_detection();
    test_thread_safety(); test_reset();
    std::cout << "\nAll 4 tests passed.\n";
}
