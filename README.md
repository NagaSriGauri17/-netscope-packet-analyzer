# NetScope — C++ Network Packet Analyzer

High-performance C++23 packet analysis engine demonstrating secure coding,
clean architecture, and real-time anomaly detection.

## Architecture

```
Raw bytes (libpcap / PCAP file)
       |
       v
 PacketParser          zero-copy frame decoder (Ethernet → IPv4 → TCP/UDP/ICMP)
       |
       v
 Packet                domain model: protocol, IPs, ports, flags, payload
       |
       v
 TrafficAnalyzer       thread-safe statistics + anomaly detection
       |
  +----+----+
  v         v
FlowStats  Anomaly[]   per-flow metrics, AI-flagged security events
```

## Anomaly Detectors

| Detector | Method | Confidence |
|---|---|---|
| Port scan | SYN rate to distinct ports (sliding 3s window) | up to 100% |
| DNS amplification | Response-to-query size ratio (>2KB response) | up to 100% |
| ICMP flood | ICMP pkt/s threshold per source | 92% |

## Building

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Requires: GCC 12+ or Clang 16+ with C++23 support.

## Secure coding features

- `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2` enabled
- `-Werror` — zero warnings policy
- `std::optional` return type prevents null-pointer dereference
- `std::span` eliminates buffer overread in header parsing
- `std::mutex` + `std::atomic` for thread-safe ingestion
