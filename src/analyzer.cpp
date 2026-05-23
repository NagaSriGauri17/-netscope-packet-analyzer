#include "analyzer.h"
#include <algorithm>
#include <chrono>
#include <sstream>

namespace netscope {

using namespace std::chrono_literals;

static constexpr int   PORT_SCAN_THRESHOLD    = 20;
static constexpr auto  PORT_SCAN_WINDOW       = 3s;
static constexpr uint32_t DNS_AMP_SIZE_THRESHOLD = 2048;

void FlowStats::update(const Packet& p) {
    ++packet_count;
    byte_count += p.length;
    avg_ttl      = avg_ttl + (p.ttl - avg_ttl) / packet_count;
    avg_pkt_size = avg_pkt_size + (p.length - avg_pkt_size) / packet_count;
}

TrafficAnalyzer::TrafficAnalyzer(AnomalyCallback cb) : on_anomaly_(std::move(cb)) {}

void TrafficAnalyzer::ingest(const Packet& pkt) {
    total_packets_.fetch_add(1, std::memory_order_relaxed);
    total_bytes_.fetch_add(pkt.length, std::memory_order_relaxed);
    std::lock_guard lock(mutex_);
    std::ostringstream key;
    key << pkt.src_str() << "->" << pkt.dst_str() << "/" << pkt.protocol_str();
    auto& flow = flows_[key.str()];
    flow.src = pkt.src_str(); flow.dst = pkt.dst_str(); flow.protocol = pkt.protocol;
    flow.update(pkt);
    detect_port_scan(pkt);
    detect_dns_amplif(pkt);
    detect_icmp_flood(pkt);
}

void TrafficAnalyzer::detect_port_scan(const Packet& pkt) {
    if (pkt.protocol != Protocol::TCP) return;
    if (pkt.flags.find("SYN") == std::string::npos) return;
    if (pkt.flags.find("ACK") != std::string::npos) return;
    auto now = Packet::Clock::now();
    auto& port_map = syn_tracker_[pkt.src_ip];
    port_map[pkt.dst_port] = now;
    std::erase_if(port_map, [&](const auto& kv) {
        return (now - kv.second) > PORT_SCAN_WINDOW;
    });
    if (static_cast<int>(port_map.size()) >= PORT_SCAN_THRESHOLD) {
        double conf = std::min(1.0, port_map.size() / 50.0);
        anomalies_.push_back({Severity::WARNING,
            "Port scan: " + std::to_string(port_map.size()) + " distinct SYN targets in 3s",
            pkt.src_ip, conf, now});
        if (on_anomaly_) on_anomaly_(anomalies_.back());
        port_map.clear();
    }
}

void TrafficAnalyzer::detect_dns_amplif(const Packet& pkt) {
    if (pkt.protocol != Protocol::DNS) return;
    if (pkt.src_port != 53) return;
    if (pkt.length < DNS_AMP_SIZE_THRESHOLD) return;
    double ratio = static_cast<double>(pkt.length) / 512.0;
    anomalies_.push_back({Severity::WARNING,
        "DNS amplification: " + std::to_string(pkt.length) + "B response (" +
        std::to_string(static_cast<int>(ratio)) + "x ratio)",
        pkt.dst_ip, std::min(1.0, ratio / 10.0), Packet::Clock::now()});
    if (on_anomaly_) on_anomaly_(anomalies_.back());
}

void TrafficAnalyzer::detect_icmp_flood(const Packet& pkt) {
    if (pkt.protocol != Protocol::ICMP) return;
    uint64_t icmp_count = 0;
    for (const auto& [k, f] : flows_)
        if (f.src.find(pkt.src_ip) != std::string::npos && f.protocol == Protocol::ICMP)
            icmp_count += f.packet_count;
    if (icmp_count > 500) {
        anomalies_.push_back({Severity::CRITICAL,
            "ICMP flood: " + std::to_string(icmp_count) + " ICMP pkts from host",
            pkt.src_ip, 0.92, Packet::Clock::now()});
        if (on_anomaly_) on_anomaly_(anomalies_.back());
    }
}

std::map<std::string, FlowStats> TrafficAnalyzer::get_flow_stats() const {
    std::lock_guard lock(mutex_); return flows_;
}
std::vector<Anomaly> TrafficAnalyzer::get_anomalies() const {
    std::lock_guard lock(mutex_); return anomalies_;
}
uint64_t TrafficAnalyzer::total_packets() const { return total_packets_.load(); }
uint64_t TrafficAnalyzer::total_bytes()   const { return total_bytes_.load(); }
void TrafficAnalyzer::reset() {
    std::lock_guard lock(mutex_);
    flows_.clear(); anomalies_.clear(); syn_tracker_.clear();
    total_packets_ = 0; total_bytes_ = 0;
}

} // namespace netscope
