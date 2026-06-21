#pragma once
#include <string>

namespace Config {
    // Network interface to sniff.
    //
    // Windows: Npcap device names look like "\Device\NPF_{GUID}", which
    //          isn't practical to hardcode. PacketSniffer::resolve_interface()
    //          will instead try to match this value against the *description*
    //          of each adapter returned by pcap_findalldevs() (e.g. "Wi-Fi",
    //          "Ethernet", "Realtek PCIe GbE Family Controller"). Run the
    //          program once — it prints all available adapters and their
    //          descriptions at startup — then set this to a string that
    //          matches the adapter you want.
    //
    // Linux:   the actual interface name, e.g. "eth0", "wlan0", "enp3s0".
#if defined(_WIN32) || defined(_WIN64)
    inline const std::string INTERFACE         = "Wi-Fi";
#else
    inline const std::string INTERFACE         = "eth0";
#endif

    // CSV paths
    inline const std::string TRAFFIC_LOG_CSV   = "data/traffic_logs.csv";

    // Python ML service connection
    inline const std::string ML_SERVICE_HOST   = "127.0.0.1";
    inline const int         ML_SERVICE_PORT   = 9999;
    inline const int         ML_CONNECT_TIMEOUT_MS = 3000;

    // Collector
    inline const int         BUFFER_SIZE       = 50;

    // Alert beep
    inline const int         ALERT_BEEP_FREQ   = 1200;   // Hz
    inline const int         ALERT_BEEP_DUR    = 500;    // ms
}
