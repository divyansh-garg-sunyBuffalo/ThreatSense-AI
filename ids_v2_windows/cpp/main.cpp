#include "core/PacketSniffer.h"
#include "core/FeatureEngineer.h"
#include "core/Collector.h"
#include "detection/ThreatDetector.h"
#include "response/AlertManager.h"
#include "response/FirewallController.h"
#include "utils/Logger.h"
#include "utils/Config.h"

#include <thread>
#include <memory>
#include <atomic>
#include <csignal>

#if defined(_WIN32) || defined(_WIN64)
    #include <pcap.h>
    #include <windows.h>
#endif

std::atomic<bool> g_running(true);

void on_signal(int) {
    Logger::log("Shutting down IDS...");
    g_running = false;
}

#if defined(_WIN32) || defined(_WIN64)
// Lists Npcap-visible adapters so the user can match Config::INTERFACE
// against a friendly description (e.g. "Wi-Fi", "Ethernet").
static void print_interfaces() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE]{};
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        Logger::error("pcap_findalldevs: " + std::string(errbuf));
        Logger::error("Is Npcap installed? https://npcap.com");
        return;
    }
    Logger::log("Available capture adapters:");
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::string desc = d->description ? d->description : "(no description)";
        Logger::log("  " + std::string(d->name ? d->name : "?") + "  -- " + desc);
    }
    pcap_freealldevs(alldevs);
}

// Windows consoles need ENABLE_VIRTUAL_TERMINAL_PROCESSING for the ANSI
// color codes used by AlertManager to render correctly.
static void enable_ansi_console() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return;
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
#endif

int main() {
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

#if defined(_WIN32) || defined(_WIN64)
    enable_ansi_console();
#endif

    Logger::init("ids.log");
    Logger::log("=== AI Cybersecurity IDS (C++ backend) starting ===");
    Logger::log("ML service expected at " + Config::ML_SERVICE_HOST
                + ":" + std::to_string(Config::ML_SERVICE_PORT));

#if defined(_WIN32) || defined(_WIN64)
    print_interfaces();
    Logger::log("Configured interface (Config::INTERFACE): " + Config::INTERFACE);
    Logger::log("If capture doesn't start, edit Config::INTERFACE to match one "
                 "of the adapter descriptions above, and run this program as "
                 "Administrator (required for raw packet capture and firewall rules).");
#endif

    auto firewall  = std::make_shared<FirewallController>();
    auto alert     = std::make_shared<AlertManager>();
    auto detector  = std::make_shared<ThreatDetector>(firewall, alert);
    auto engineer  = std::make_shared<FeatureEngineer>();
    auto collector = std::make_shared<Collector>();

    PacketSniffer sniffer(Config::INTERFACE);

    auto packet_handler = [&](const PacketData& pkt) {
        std::cout << "PACKET: "
                << pkt.src_ip << " -> "
                << pkt.dst_ip
                << " | " << pkt.protocol
                << " | " << pkt.packet_size
                << std::endl;

        collector->collect(pkt);
        Features feat = engineer->build_features(pkt);
        detector->analyze(feat);
    };

    Logger::log("Starting sniffer on interface: " + Config::INTERFACE);
    Logger::log("Press Ctrl+C to stop.");

    std::thread sniffer_thread([&]() {
        sniffer.start(packet_handler, g_running);
    });

    sniffer_thread.join();
    collector->flush_all();
    Logger::log("IDS stopped cleanly.");
    return 0;
}
