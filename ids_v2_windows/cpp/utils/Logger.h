#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>

class Logger {
public:
    static void init(const std::string& filename = "ids.log") {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!file_.is_open())
            file_.open(filename, std::ios::app);
    }

    static void log(const std::string& msg)   { write("[INFO] ", msg); }
    static void error(const std::string& msg) { write("[ERROR]", msg, true); }
    static void warn(const std::string& msg)  { write("[WARN] ", msg); }

private:
    static void write(const char* level, const std::string& msg, bool is_err = false) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::string entry = ts() + " " + level + " " + msg;
        (is_err ? std::cerr : std::cout) << entry << "\n";
        if (file_.is_open()) { file_ << entry << "\n"; file_.flush(); }
    }

    // std::localtime is not thread-safe and triggers deprecation warnings
    // (C4996) under MSVC. Use the platform-appropriate thread-safe variant.
    static std::string ts() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
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

    static inline std::mutex    mtx_;
    static inline std::ofstream file_;
};
