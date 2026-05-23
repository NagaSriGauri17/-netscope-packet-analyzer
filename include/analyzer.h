#pragma once
#include "packet.h"
#include <functional>
#include <map>
#include <vector>
#include <atomic>
#include <mutex>
#include <string>

namespace netscope {

struct FlowStats {
    std::string  src;
    std::string  dst;
    Protocol     protocol;
    uint64_t     packet_count{0};
    uint64_t     byte_count{0};
    double       avg_ttl{0.0};
    double       avg_pkt_size{0.0};
    void update(const Packet& p);
};

enum class Severity { INFO, WARNING, CRITICAL };

struct Anomaly {
    Severity    severity;
    std::string description;
    std::string src_ip;
    double      confidence;
    Packet::Clock::time_point detected_at;
};

using AnomalyCallback = std::function<void(const Anomaly&)>;

/**
 * TrafficAnalyzer - real-time statistical analysis engine.
 *
 * Thread-safe: ingest() may be called from a capture thread while
 * query methods are called from a UI/reporting thread.
 *
 * Anomaly detectors:
 *   1. Port scan (SYN rate to distinct ports per source, sliding window)
 *   2. DNS amplification (response-to-request size ratio)
 *   3. ICMP flood (threshold-based packet rate)
 */
class TrafficAnalyzer {
public:
    explicit TrafficAnalyzer(AnomalyCallback on_anomaly = nullptr);

    void ingest(const Packet& pkt);   // thread-safe

    std::map<std::string, FlowStats> get_flow_stats() const;
    std::vector<Anomaly>             get_anomalies()   const;
    uint64_t                         total_packets()   const;
    uint64_t                         total_bytes()     const;
    void reset();

private:
    void detect_port_scan  (const Packet& pkt);
    void detect_dns_amplif (const Packet& pkt);
    void detect_icmp_flood (const Packet& pkt);

    mutable std::mutex               mutex_;
    std::map<std::string, FlowStats> flows_;
    std::vector<Anomaly>             anomalies_;
    std::atomic<uint64_t>            total_packets_{0};
    std::atomic<uint64_t>            total_bytes_{0};
    std::map<std::string, std::map<uint16_t, Packet::Clock::time_point>> syn_tracker_;
    AnomalyCallback on_anomaly_;
};

} // namespace netscope
