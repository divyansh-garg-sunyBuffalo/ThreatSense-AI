#pragma once
#include "../utils/Logger.h"

#include <string>
#include <unordered_set>
#include <mutex>
#include <cstdlib>

class FirewallController {
public:
    void block_ip(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (blocked_.count(ip)) return;
        blocked_.insert(ip);

#if defined(_WIN32) || defined(_WIN64)
        // Requires running as Administrator. Adds both inbound and outbound
        // block rules via netsh advfirewall.
        std::string cmd =
            "netsh advfirewall firewall add rule "
            "name=\"IDS Block " + ip + " (in)\" "
            "dir=in action=block remoteip=" + ip +
            " & netsh advfirewall firewall add rule "
            "name=\"IDS Block " + ip + " (out)\" "
            "dir=out action=block remoteip=" + ip;
#else
        std::string cmd = "nft add rule inet filter input ip saddr " + ip + " drop 2>/dev/null"
                          " || iptables -I INPUT -s " + ip + " -j DROP";
#endif
        int ret = std::system(cmd.c_str());
        if (ret == 0) {
            Logger::log("Firewall: blocked " + ip);
        } else {
#if defined(_WIN32) || defined(_WIN64)
            Logger::error("Firewall: failed to block " + ip
                           + " (re-run as Administrator)");
#else
            Logger::error("Firewall: failed to block " + ip
                           + " (re-run as root, or check nft/iptables availability)");
#endif
        }
    }

    void unblock_ip(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mtx_);
        blocked_.erase(ip);
#if defined(_WIN32) || defined(_WIN64)
        std::string cmd =
            "netsh advfirewall firewall delete rule name=\"IDS Block " + ip + " (in)\""
            " & netsh advfirewall firewall delete rule name=\"IDS Block " + ip + " (out)\"";
#else
        std::string cmd = "nft delete rule inet filter input ip saddr " + ip + " drop 2>/dev/null"
                          " || iptables -D INPUT -s " + ip + " -j DROP";
#endif
        std::system(cmd.c_str());
        Logger::log("Firewall: unblocked " + ip);
    }

private:
    std::unordered_set<std::string> blocked_;
    std::mutex mtx_;
};
