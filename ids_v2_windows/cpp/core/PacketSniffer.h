#pragma once
#include "../common/Types.h"
#include "../utils/Logger.h"

#include <pcap.h>
#include <functional>
#include <atomic>
#include <string>
#include <cstdint>
#include <cstring>

// ── Cross-platform networking headers ────────────────────────────────────────
// <netinet/ip.h>, <netinet/tcp.h>, <netinet/udp.h> and the BSD `struct ip` /
// `struct tcphdr` / `struct udphdr` field names (ip_hl, ip_p, th_sport, ...)
// don't exist on Windows. To stay portable we define our own minimal,
// byte-for-byte-compatible header layouts below and only rely on
// <winsock2.h>/<ws2tcpip.h> (Windows) or <arpa/inet.h> (Linux) for
// ntohs()/inet_ntop().
#if defined(_WIN32) || defined(_WIN64)
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600   // Vista+, required for inet_ntop
    #endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

#define ETH_HDR_LEN 14
#define PROTO_TCP   6
#define PROTO_UDP   17

#pragma pack(push, 1)
struct IPv4Header {
    uint8_t  ver_ihl;       // version (high 4 bits) + header length in 32-bit words (low 4 bits)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;      // network byte order
    uint32_t dst_addr;      // network byte order
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

class PacketSniffer {
public:
    using Callback = std::function<void(const PacketData&)>;

    explicit PacketSniffer(const std::string& iface) : iface_(resolve_interface(iface)) {}

    void start(Callback cb, std::atomic<bool>& running) {
        char errbuf[PCAP_ERRBUF_SIZE]{};
        pcap_t* handle = pcap_open_live(iface_.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            Logger::error("pcap_open_live: " + std::string(errbuf));
            return;
        }
        Logger::log("Packet capture started on " + iface_);

        struct pcap_pkthdr* hdr;
        const u_char*       data;
        while (running.load()) {
            int r = pcap_next_ex(handle, &hdr, &data);
            if (r == 0) continue;  // timeout, no packet
            if (r < 0)  break;     // error or EOF
            PacketData pkt = parse(data, static_cast<int>(hdr->len));
            cb(pkt);
        }
        pcap_close(handle);
        Logger::log("Packet capture stopped.");
    }

private:
    // On Windows, Config::INTERFACE is typically a human-friendly fragment
    // (e.g. "Wi-Fi", "Ethernet") rather than the raw Npcap device name
    // (\Device\NPF_{GUID}). This looks up pcap_findalldevs() and:
    //   1. returns an exact match on device name if found, else
    //   2. returns the device whose *description* contains the given
    //      string, else
    //   3. falls back to returning the input unchanged (Linux interface
    //      names like "eth0" already match directly, so this is a no-op).
    static std::string resolve_interface(const std::string& name) {
        pcap_if_t* alldevs;
        char errbuf[PCAP_ERRBUF_SIZE]{};
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            Logger::warn("pcap_findalldevs: " + std::string(errbuf));
            return name;
        }

        std::string result = name;
        bool found = false;

        for (pcap_if_t* d = alldevs; d; d = d->next) {
            std::string devname = d->name ? d->name : "";
            if (devname == name) { result = devname; found = true; break; }
        }
        if (!found) {
            for (pcap_if_t* d = alldevs; d; d = d->next) {
                std::string devname = d->name ? d->name : "";
                std::string desc    = d->description ? d->description : "";
                if (!desc.empty() && desc.find(name) != std::string::npos) {
                    result = devname;
                    found  = true;
                    break;
                }
            }
        }
        pcap_freealldevs(alldevs);

        if (!found) {
            Logger::warn("PacketSniffer: no adapter matching \"" + name
                            + "\" found; trying it verbatim. Run the program to "
                            "see the list of available adapters.");
        }
        return result;
    }

    PacketData parse(const u_char* raw, int len) {
        if (len < ETH_HDR_LEN + static_cast<int>(sizeof(IPv4Header))) return {};

        const auto* ip = reinterpret_cast<const IPv4Header*>(raw + ETH_HDR_LEN);
        int ip_hl = (ip->ver_ihl & 0x0F) * 4;
        if (ip_hl < 20 || ETH_HDR_LEN + ip_hl > len) return {};

        PacketData pkt;
        pkt.src_ip      = ip_to_string(ip->src_addr);
        pkt.dst_ip      = ip_to_string(ip->dst_addr);
        pkt.packet_size = len;

        const u_char* tp        = raw + ETH_HDR_LEN + ip_hl;
        int           remaining = len - ETH_HDR_LEN - ip_hl;

        if (ip->protocol == PROTO_TCP && remaining >= static_cast<int>(sizeof(TCPHeader))) {
            const auto* tcp = reinterpret_cast<const TCPHeader*>(tp);
            pkt.protocol = "TCP";
            pkt.src_port = ntohs(tcp->src_port);
            pkt.dst_port = ntohs(tcp->dst_port);
        } else if (ip->protocol == PROTO_UDP && remaining >= static_cast<int>(sizeof(UDPHeader))) {
            const auto* udp = reinterpret_cast<const UDPHeader*>(tp);
            pkt.protocol = "UDP";
            pkt.src_port = ntohs(udp->src_port);
            pkt.dst_port = ntohs(udp->dst_port);
        } else {
            pkt.protocol = "OTHER";
        }
        return pkt;
    }

    static std::string ip_to_string(uint32_t addr_net_order) {
        in_addr a{};
        a.s_addr = addr_net_order;
        char buf[INET_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return "0.0.0.0";
        return std::string(buf);
    }

    std::string iface_;
};
