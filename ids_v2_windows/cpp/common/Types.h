#pragma once
#include <string>
#include <vector>

// Raw data extracted from a network packet
struct PacketData {
    std::string src_ip    = "0.0.0.0";
    std::string dst_ip    = "0.0.0.0";
    std::string protocol  = "OTHER";
    int         src_port  = 0;
    int         dst_port  = 0;
    int         packet_size = 0;
};

// Numeric feature vector sent to Python ML service
struct Features {
    std::string src_ip    = "0.0.0.0";
    std::string dst_ip    = "0.0.0.0";
    int         src_port  = 0;
    int         dst_port  = 0;
    int         packet_size = 0;
    int         is_tcp    = 0;
    int         is_udp    = 0;
};

// Result returned from Python ML service
struct DetectionResult {
    std::string status;       // "NORMAL" or "THREAT"
    std::string attack_type;  // e.g. "DDoS", "PortScan"
};
