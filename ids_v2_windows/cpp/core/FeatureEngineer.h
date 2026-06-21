#pragma once
#include "../common/Types.h"

class FeatureEngineer {
public:
    Features build_features(const PacketData& pkt) const {
        Features f;
        f.src_ip      = pkt.src_ip;
        f.dst_ip      = pkt.dst_ip;
        f.src_port    = pkt.src_port;
        f.dst_port    = pkt.dst_port;
        f.packet_size = pkt.packet_size;
        f.is_tcp      = (pkt.protocol == "TCP") ? 1 : 0;
        f.is_udp      = (pkt.protocol == "UDP") ? 1 : 0;
        return f;
    }
};
