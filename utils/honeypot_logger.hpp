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
        j["src_mac"] = getMacFromIp(src_ip);
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

    std::string getMacFromIp(const std::string& ip_with_port) {
        if (ip_with_port.empty() || ip_with_port == "0.0.0.0" || ip_with_port == "127.0.0.1" || ip_with_port == "UNKNOWN_MAC" || ip_with_port == "MULTIPLE") return "UNKNOWN_MAC";
        
        // If it's already a MAC address (e.g. from GOOSE)
        if (ip_with_port.length() == 17 && ip_with_port[2] == ':') {
            return ip_with_port;
        }

        std::string ip = ip_with_port;
        size_t colon_pos = ip.find(":");
        if (colon_pos != std::string::npos) {
            ip = ip.substr(0, colon_pos);
        }

        std::ifstream arp_file("/proc/net/arp");
        if (!arp_file.is_open()) return "UNKNOWN_MAC";
        
        std::string line;
        // Skip header
        std::getline(arp_file, line);
        while (std::getline(arp_file, line)) {
            // Format: IP address       HW type     Flags       HW address            Mask     Device
            size_t pos = line.find(ip);
            if (pos == 0 && line.length() > ip.length() && line[ip.length()] == ' ') {
                // Find HW address
                size_t mac_pos = line.find(":", ip.length());
                if (mac_pos != std::string::npos && mac_pos >= 2) {
                    mac_pos -= 2; // Move back to start of MAC
                    return line.substr(mac_pos, 17);
                }
            }
        }
        return "UNKNOWN_MAC";
    }

    std::string hexDump(const std::string& data) {
        if (data.empty()) return "";
        std::string result;
        char buf[8];
        for (unsigned char c : data) {
            snprintf(buf, sizeof(buf), "%02X ", c);
            result += buf;
        }
        return result;
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
