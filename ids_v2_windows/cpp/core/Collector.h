#pragma once
#include "../common/Types.h"
#include "../utils/Logger.h"
#include "../utils/Config.h"

#include <vector>
#include <mutex>
#include <fstream>
#include <filesystem>

class Collector {
public:
    Collector() {
        std::filesystem::create_directories("data");
        if (!std::filesystem::exists(Config::TRAFFIC_LOG_CSV)) {
            std::ofstream f(Config::TRAFFIC_LOG_CSV);
            f << "src_ip,dst_ip,protocol,src_port,dst_port,packet_size\n";
        }
    }

    void collect(const PacketData& pkt) {
        std::lock_guard<std::mutex> lock(mtx_);
        buf_.push_back(pkt);
        if (static_cast<int>(buf_.size()) >= Config::BUFFER_SIZE)
            flush();
    }

    void flush_all() {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!buf_.empty()) flush();
    }

private:
    void flush() {
        std::ofstream f(Config::TRAFFIC_LOG_CSV, std::ios::app);
        if (!f) { Logger::error("Cannot open traffic CSV."); return; }
        for (const auto& p : buf_) {
            f << p.src_ip    << ',' << p.dst_ip   << ','
              << p.protocol  << ',' << p.src_port << ','
              << p.dst_port  << ',' << p.packet_size << '\n';
        }
        Logger::log("Saved " + std::to_string(buf_.size()) + " packets to CSV.");
        buf_.clear();
    }

    std::vector<PacketData> buf_;
    std::mutex              mtx_;
};
