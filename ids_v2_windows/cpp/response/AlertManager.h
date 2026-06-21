#pragma once
#include "../utils/Logger.h"
#include "../utils/Config.h"

#include <string>
#include <fstream>
#include <mutex>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
#endif

class AlertManager {
public:
    AlertManager() {
        file_.open("security_alerts.log", std::ios::app);
    }

    void send_alert(const std::string& message) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::string entry = ts() + " [ALERT] " + message;

        // Red console output. On Windows 10+ this requires
        // ENABLE_VIRTUAL_TERMINAL_PROCESSING to be set on the console
        // (done once in main()), otherwise the raw escape codes will be
        // printed instead of colored text.
        std::cout << "\033[1;31m" << entry << "\033[0m\n" << std::flush;

        if (file_.is_open()) { file_ << entry << "\n"; file_.flush(); }

        beep();
    }

private:
    static std::string ts() {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#if defined(_WIN32) || defined(_WIN64)
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::ostringstream ss;
        ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    static void beep() {
#if defined(_WIN32) || defined(_WIN64)
        ::Beep(static_cast<DWORD>(Config::ALERT_BEEP_FREQ),
               static_cast<DWORD>(Config::ALERT_BEEP_DUR));
#else
        std::cout << '\a' << std::flush;
        std::system("beep -f 1200 -l 500 2>/dev/null || true");
#endif
    }

    std::ofstream file_;
    std::mutex    mtx_;
};
