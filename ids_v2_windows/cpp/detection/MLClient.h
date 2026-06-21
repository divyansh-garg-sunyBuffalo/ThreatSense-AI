#pragma once
/*
 * MLClient — sends a feature vector to the Python ML service over TCP.
 *
 * Protocol (newline-delimited JSON):
 *   C++ → Python:  {"packet_size":512,"is_tcp":1,"is_udp":0,"src_port":12345,"dst_port":80,"src_ip":"1.2.3.4","dst_ip":"5.6.7.8"}\n
 *   Python → C++:  {"status":"THREAT","attack_type":"DDoS"}\n
 *                  {"status":"NORMAL","attack_type":""}\n
 *
 * A new TCP connection is made per packet (simple, no keep-alive needed at
 * typical IDS throughput; upgrade to connection pooling if needed).
 */

#include "../common/Types.h"
#include "../utils/Logger.h"
#include "../utils/Config.h"

#include <string>
#include <sstream>
#include <stdexcept>

// ── Platform socket headers ──────────────────────────────────────────────────
#if defined(_WIN32) || defined(_WIN64)
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600   // Vista+, required for inet_pton
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using sock_t = SOCKET;
  #define INVALID_SOCK INVALID_SOCKET
  #define CLOSE_SOCK(s) closesocket(s)
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  using sock_t = int;
  #define INVALID_SOCK (-1)
  #define CLOSE_SOCK(s) ::close(s)
#endif

class MLClient {
public:
    MLClient() {
#if defined(_WIN32) || defined(_WIN64)
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    }

    ~MLClient() {
#if defined(_WIN32) || defined(_WIN64)
        WSACleanup();
#endif
    }

    // Send features → get DetectionResult from Python ML service.
    // Returns NORMAL on connection failure (fail-open) so IDS keeps running.
    DetectionResult predict(const Features& f) {
        std::string payload = features_to_json(f) + "\n";

        sock_t sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCK) {
            Logger::error("MLClient: socket() failed");
            return {"NORMAL", ""};
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(Config::ML_SERVICE_PORT));
        inet_pton(AF_INET, Config::ML_SERVICE_HOST.c_str(), &addr.sin_addr);

        if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            Logger::warn("MLClient: cannot connect to Python ML service at "
                         + Config::ML_SERVICE_HOST + ":" + std::to_string(Config::ML_SERVICE_PORT));
            CLOSE_SOCK(sock);
            return {"NORMAL", ""};
        }

        // Send JSON payload
        ::send(sock, payload.c_str(), static_cast<int>(payload.size()), 0);

        // Receive response (read until newline)
        std::string response;
        char buf[4096];
        while (true) {
            int n = ::recv(sock, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            response += buf;
            if (response.find('\n') != std::string::npos) break;
        }
        CLOSE_SOCK(sock);

        return parse_response(response);
    }

private:
    // Minimal JSON serialiser — no external library needed
    static std::string features_to_json(const Features& f) {
        std::ostringstream ss;
        ss << "{"
           << "\"packet_size\":"  << f.packet_size  << ","
           << "\"is_tcp\":"       << f.is_tcp        << ","
           << "\"is_udp\":"       << f.is_udp        << ","
           << "\"src_port\":"     << f.src_port      << ","
           << "\"dst_port\":"     << f.dst_port      << ","
           << "\"src_ip\":\""     << f.src_ip        << "\","
           << "\"dst_ip\":\""     << f.dst_ip        << "\""
           << "}";
        return ss.str();
    }

    // Minimal JSON parser for the fixed response schema
    static DetectionResult parse_response(const std::string& json) {
        DetectionResult r{"NORMAL", ""};
        auto extract = [&](const std::string& key) -> std::string {
            auto pos = json.find("\"" + key + "\":\"");
            if (pos == std::string::npos) return "";
            pos += key.size() + 4;
            auto end = json.find('"', pos);
            return (end == std::string::npos) ? "" : json.substr(pos, end - pos);
        };
        r.status      = extract("status");
        r.attack_type = extract("attack_type");
        if (r.status.empty()) r.status = "NORMAL";
        return r;
    }
};
