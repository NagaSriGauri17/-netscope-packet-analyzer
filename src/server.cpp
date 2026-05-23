/**
 * NetScope WebSocket Server — v2 with anomaly log file
 *
 * NEW in this version:
 *   - Anomalies are saved to  anomalies.log  next to the binary
 *   - Each log line: [timestamp] SEVERITY | src_ip | description | confidence
 *
 * Build & run:
 *   cmake -B build && cmake --build build
 *   ./build/netscope_server
 *   Then open dashboard/index.html in your browser
 */

#include "packet.h"
#include "analyzer.h"
#include "parser.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>       // ← NEW: for writing the log file
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace netscope;
using namespace std::chrono_literals;

// ─────────────────────────────────────────────
// Anomaly log file
// ─────────────────────────────────────────────
// This is the new feature: every time an anomaly is detected,
// we write one line to anomalies.log so it is saved permanently.
//
// Format:
//   [2026-05-20 16:44:01] WARNING  | 192.168.1.45 | Port scan: 23 targets | conf=0.92
//
std::mutex    log_mutex;
std::ofstream log_file;

void open_log_file() {
    // Opens (or creates) anomalies.log in the current working directory
    log_file.open("anomalies.log", std::ios::app);  // app = append, never overwrite
    if (!log_file.is_open()) {
        std::cerr << "[warn] Could not open anomalies.log for writing\n";
        return;
    }
    // Write a header line so we know when this session started
    std::time_t now = std::time(nullptr);
    char ts[32]; std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    log_file << "\n=== NetScope session started " << ts << " ===\n";
    log_file.flush();
    std::cout << "[log] Anomalies will be saved to anomalies.log\n";
}

void log_anomaly(const Anomaly& a) {
    if (!log_file.is_open()) return;

    // Get current timestamp as readable string
    std::time_t now = std::time(nullptr);
    char ts[32]; std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    // Severity as string
    const char* sev = (a.severity == Severity::CRITICAL) ? "CRITICAL" : "WARNING ";

    // Write one line per anomaly
    std::lock_guard lock(log_mutex);
    log_file << "[" << ts << "] "
             << sev   << " | "
             << a.src_ip << " | "
             << a.description << " | "
             << "conf=" << a.confidence << "\n";
    log_file.flush();   // flush immediately so the file is always up to date
}

// ─────────────────────────────────────────────
// Base64 encode (WebSocket handshake requirement)
// ─────────────────────────────────────────────
static const char B64C[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string base64_encode(const uint8_t* d, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = (uint32_t)d[i] << 16;
        if (i+1 < len) b |= (uint32_t)d[i+1] << 8;
        if (i+2 < len) b |= d[i+2];
        out += B64C[(b>>18)&63]; out += B64C[(b>>12)&63];
        out += (i+1<len) ? B64C[(b>>6)&63] : '=';
        out += (i+2<len) ? B64C[b&63]      : '=';
    }
    return out;
}

// ─────────────────────────────────────────────
// Minimal SHA-1 (required by WebSocket spec)
// ─────────────────────────────────────────────
struct SHA1 {
    uint32_t h[5]{0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
    uint8_t buf[64]{}; size_t buf_len=0, total=0;
    static uint32_t rol(uint32_t v,int n){ return (v<<n)|(v>>(32-n)); }
    void process(const uint8_t* blk){
        uint32_t w[80],a,b,c,d,e,f,k,t;
        for(int i=0;i<16;i++) w[i]=(blk[i*4]<<24)|(blk[i*4+1]<<16)|(blk[i*4+2]<<8)|blk[i*4+3];
        for(int i=16;i<80;i++) w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
        a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];
        for(int i=0;i<80;i++){
            if(i<20){f=(b&c)|(~b&d);k=0x5A827999;}
            else if(i<40){f=b^c^d;k=0x6ED9EBA1;}
            else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
            else{f=b^c^d;k=0xCA62C1D6;}
            t=rol(a,5)+f+e+k+w[i];e=d;d=c;c=rol(b,30);b=a;a=t;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
    }
    void update(const uint8_t* data, size_t len){
        total+=len;
        while(len){ size_t cp=std::min(len,64-buf_len);
            memcpy(buf+buf_len,data,cp); buf_len+=cp; data+=cp; len-=cp;
            if(buf_len==64){process(buf);buf_len=0;} }
    }
    void finish(uint8_t out[20]){
        uint64_t bits=total*8; uint8_t p=0x80; update(&p,1);
        while(buf_len!=56){p=0;update(&p,1);}
        uint8_t b[8]; for(int i=7;i>=0;i--){b[i]=bits&0xFF;bits>>=8;} update(b,8);
        for(int i=0;i<5;i++){out[i*4]=(h[i]>>24)&0xFF;out[i*4+1]=(h[i]>>16)&0xFF;out[i*4+2]=(h[i]>>8)&0xFF;out[i*4+3]=h[i]&0xFF;}
    }
};

std::string ws_accept(const std::string& key){
    std::string s=key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    SHA1 sha; sha.update((const uint8_t*)s.data(),s.size());
    uint8_t d[20]; sha.finish(d); return base64_encode(d,20);
}

// ─────────────────────────────────────────────
// WebSocket frame sender
// ─────────────────────────────────────────────
bool ws_send(int fd, const std::string& msg){
    size_t len=msg.size();
    std::vector<uint8_t> frame;
    frame.push_back(0x81);
    if(len<126) frame.push_back((uint8_t)len);
    else if(len<65536){frame.push_back(126);frame.push_back((len>>8)&0xFF);frame.push_back(len&0xFF);}
    else{frame.push_back(127);for(int i=7;i>=0;i--)frame.push_back((len>>(i*8))&0xFF);}
    frame.insert(frame.end(),msg.begin(),msg.end());
    return ::send(fd,frame.data(),frame.size(),MSG_NOSIGNAL)>0;
}

// ─────────────────────────────────────────────
// Connected clients
// ─────────────────────────────────────────────
std::mutex       clients_mtx;
std::vector<int> clients;

void broadcast(const std::string& msg){
    std::lock_guard lock(clients_mtx);
    for(auto it=clients.begin();it!=clients.end();){
        if(!ws_send(*it,msg)){ close(*it); it=clients.erase(it); }
        else ++it;
    }
}

// ─────────────────────────────────────────────
// JSON builders
// ─────────────────────────────────────────────
std::string pkt_json(const Packet& p){
    std::ostringstream o;
    o<<"{\"type\":\"packet\""
     <<",\"src_ip\":\""<<p.src_ip<<"\""
     <<",\"dst_ip\":\""<<p.dst_ip<<"\""
     <<",\"src_port\":"<<p.src_port
     <<",\"dst_port\":"<<p.dst_port
     <<",\"protocol\":\""<<p.protocol_str()<<"\""
     <<",\"flags\":\""<<p.flags<<"\""
     <<",\"length\":"<<p.length<<"}";
    return o.str();
}
std::string stats_json(uint64_t pps, int mbps, uint64_t total){
    std::ostringstream o;
    o<<"{\"type\":\"stats\",\"pps\":"<<pps
     <<",\"throughput_mbps\":"<<mbps
     <<",\"total\":"<<total<<"}";
    return o.str();
}
std::string anom_json(const Anomaly& a){
    std::ostringstream o;
    o<<"{\"type\":\"anomaly\""
     <<",\"severity\":\""<<(a.severity==Severity::CRITICAL?"CRITICAL":"WARNING")<<"\""
     <<",\"description\":\""<<a.description<<"\""
     <<",\"src_ip\":\""<<a.src_ip<<"\""
     <<",\"confidence\":"<<a.confidence<<"}";
    return o.str();
}

// ─────────────────────────────────────────────
// WebSocket client handler
// ─────────────────────────────────────────────
void handle_client(int fd){
    char buf[4096]{}; int n=recv(fd,buf,sizeof(buf)-1,0);
    if(n<=0){close(fd);return;}
    std::string req(buf,n);
    auto pos=req.find("Sec-WebSocket-Key:");
    if(pos==std::string::npos){close(fd);return;}
    pos+=19; auto end=req.find("\r\n",pos);
    std::string key=req.substr(pos,end-pos);
    while(!key.empty()&&key.front()==' ')key.erase(0,1);
    while(!key.empty()&&(key.back()=='\r'||key.back()==' '))key.pop_back();
    std::string resp=
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: "+ws_accept(key)+"\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n";
    ::send(fd,resp.data(),resp.size(),0);
    {std::lock_guard lock(clients_mtx); clients.push_back(fd);}
    std::cout<<"[ws] client connected fd="<<fd<<"\n";
    uint8_t hdr[2];
    while(recv(fd,hdr,2,0)==2){
        uint8_t op=hdr[0]&0x0F; if(op==8)break;
        uint64_t plen=hdr[1]&0x7F; bool masked=hdr[1]&0x80;
        if(plen==126){uint8_t x[2];recv(fd,x,2,0);plen=(x[0]<<8)|x[1];}
        else if(plen==127){uint8_t x[8];recv(fd,x,8,0);plen=0;for(int i=0;i<8;i++)plen=(plen<<8)|x[i];}
        uint8_t mask[4]={};
        if(masked)recv(fd,mask,4,0);
        std::vector<uint8_t>pay(plen); recv(fd,pay.data(),plen,0);
    }
    {std::lock_guard lock(clients_mtx); std::erase(clients,fd);}
    close(fd);
    std::cout<<"[ws] client disconnected fd="<<fd<<"\n";
}

// ─────────────────────────────────────────────
// Packet simulation thread
// ─────────────────────────────────────────────
void simulate_packets(TrafficAnalyzer& analyzer, PacketParser& parser){
    const char* ips[]={"192.168.1.10","192.168.1.22","10.0.0.5","10.0.0.44",
                       "172.16.0.3","203.0.113.7","8.8.8.8","1.1.1.1"};
    const uint16_t ports[]={80,443,53,22,8080,3306,5432,12345};
    const uint8_t  protos[]={6,6,6,6,17,17,1};
    const uint8_t  tcp_flags[]={0x02,0x10,0x01,0x04,0x12,0x18};
    srand((unsigned)time(nullptr));
    while(true){
        std::vector<uint8_t> frame(sizeof(EthernetHeader)+sizeof(IPv4Header)+sizeof(TCPHeader),0);
        auto* eth=reinterpret_cast<EthernetHeader*>(frame.data());
        eth->ether_type=htons(0x0800);
        auto* ip=reinterpret_cast<IPv4Header*>(frame.data()+sizeof(EthernetHeader));
        ip->version_ihl=0x45; ip->ttl=64;
        ip->protocol=protos[rand()%7];
        ip->total_length=htons(frame.size()-sizeof(EthernetHeader));
        struct in_addr a{}; inet_aton(ips[rand()%8],&a); ip->src_ip=a.s_addr;
        inet_aton(ips[rand()%8],&a); ip->dst_ip=a.s_addr;
        auto* tcp=reinterpret_cast<TCPHeader*>(frame.data()+sizeof(EthernetHeader)+sizeof(IPv4Header));
        tcp->src_port=htons(ports[rand()%8]); tcp->dst_port=htons(ports[rand()%8]);
        tcp->data_offset_reserved=0x50; tcp->flags=tcp_flags[rand()%6];
        auto pkt=parser.parse({frame.data(),frame.size()});
        if(pkt){ analyzer.ingest(*pkt); broadcast(pkt_json(*pkt)); }
        std::this_thread::sleep_for(std::chrono::milliseconds(40+rand()%80));
    }
}

// ─────────────────────────────────────────────
// Stats broadcast thread
// ─────────────────────────────────────────────
void stats_loop(TrafficAnalyzer& analyzer){
    uint64_t last=0; size_t last_anom=0;
    while(true){
        std::this_thread::sleep_for(1s);
        uint64_t total=analyzer.total_packets();
        uint64_t pps=total-last; last=total;
        int mbps=(int)(pps*800.0/1e6);
        broadcast(stats_json(pps,mbps,total));
        auto anoms=analyzer.get_anomalies();
        if(anoms.size()>last_anom){
            for(size_t i=last_anom; i<anoms.size(); i++){
                broadcast(anom_json(anoms[i]));
                log_anomaly(anoms[i]);   // ← NEW: write to log file
            }
            last_anom=anoms.size();
        }
    }
}

// ─────────────────────────────────────────────
// main
// ─────────────────────────────────────────────
int main(){
    open_log_file();   // ← NEW: open the log file at startup

    constexpr int PORT=9001;
    int srv=socket(AF_INET,SOCK_STREAM,0);
    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr{}; addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(PORT);
    bind(srv,(sockaddr*)&addr,sizeof(addr)); listen(srv,10);

    std::cout<<"\n╔═══════════════════════════════════════╗\n";
    std::cout<<  "║   NetScope — C++ Server on port "<<PORT<<"   ║\n";
    std::cout<<  "╚═══════════════════════════════════════╝\n";
    std::cout<<"\n  1. Keep this terminal running\n";
    std::cout<<  "  2. Open  dashboard/index.html  in your browser\n";
    std::cout<<  "  3. Anomalies are saved to  anomalies.log\n\n";

    TrafficAnalyzer analyzer([](const Anomaly& a){
        std::cout<<"[ANOMALY] "<<a.src_ip<<" — "<<a.description<<"\n";
    });
    PacketParser parser;

    std::thread([&]{simulate_packets(analyzer,parser);}).detach();
    std::thread([&]{stats_loop(analyzer);}).detach();

    while(true){
        sockaddr_in ca{}; socklen_t cl=sizeof(ca);
        int cfd=accept(srv,(sockaddr*)&ca,&cl);
        if(cfd<0) continue;
        std::thread(handle_client,cfd).detach();
    }
}
