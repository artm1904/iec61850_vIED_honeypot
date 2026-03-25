#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iostream>
#include <nlohmann/json.hpp>

class HoneypotLogger {
public:
    static HoneypotLogger& getInstance() {
        static HoneypotLogger instance;
        return instance;
    }

    void init(const std::string& filepath) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.is_open()) {
            log_file_.close();
        }
        log_file_.open(filepath, std::ios::app);
        if(!log_file_.is_open()) {
            std::cerr << "Failed to open log file: " << filepath << std::endl;
        }
    }

    void logEvent(const std::string& protocol, 
                  const std::string& action,
                  const std::string& src_ip, 
                  int src_port,
                  const std::string& target, 
                  const std::string& value, 
                  const std::string& status) 
    {
        nlohmann::json j;
        j["timestamp"] = getCurrentISO8601Time();
        j["src_ip"] = src_ip;
        j["src_port"] = src_port;
        j["protocol"] = protocol;
        j["action"] = action;
        j["target"] = target;
        j["value"] = value;
        j["status"] = status;

        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.is_open()) {
            log_file_ << j.dump() << "\n";
            log_file_.flush();
        } else {
            // Fallback if not initialized properly
            std::cout << "LOG: " << j.dump() << std::endl;
        }
    }

private:
    HoneypotLogger() {}
    ~HoneypotLogger() { if (log_file_.is_open()) log_file_.close(); }

    std::string getCurrentISO8601Time() {
        char buf[sizeof "2026-01-01T12:00:00Z"];
        time_t now = time(nullptr);
        strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
        return std::string(buf);
    }

    std::ofstream log_file_;
    std::mutex mutex_;
};
