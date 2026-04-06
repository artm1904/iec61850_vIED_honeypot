#include "honeypot_logger_c_api.h"
#include "honeypot_logger.hpp"

extern "C" {
    void Logger_Init() {
        // T-Pot default path, adjust as needed in real docker env
         printf("Logger_Init start@@@@\n@@@\n@@@@\n@@@@\n@@@@@\n@@@@\n@@@@@\n@@@@\n@@@@\n@@@@@\n@@@@\n@@@\n@@@\n@@@\n");
        HoneypotLogger::getInstance().init("/var/log/tpot/vied_events.json");
    }


    // A9 - Нарушитель решил осуществить подмену информации, передаваемой по MMS, используя ПО, доступное в открытом доступе и/или самостоятельно разработанное ПО
    // A10 - Нарушитель подключится к шине станции и отправит некорректные данные по MMS, используя ПО, доступное в открытом доступе и/или самостоятельно разработанное ПО
    void Logger_LogMmsAction(const char* action, const char* src_ip, int src_port, const char* target, const char* value, const char* status) {
        HoneypotLogger::getInstance().logEvent(
            std::string("MMS"), 
            action ? std::string(action) : std::string("UNKNOWN"), 
            src_ip ? std::string(src_ip) : std::string("0.0.0.0"), 
            src_port, 
            target ? std::string(target) : std::string(""), 
            value ? std::string(value) : std::string(""), 
            status ? std::string(status) : std::string("UNKNOWN")
        );
    }

    void Logger_LogFileAccess(const char* action, const char* src_ip, int src_port, const char* filename, const char* status) {
        HoneypotLogger::getInstance().logEvent(
            std::string("MMS"), 
            action ? std::string(action) : std::string("FILE_ACCESS"),
            src_ip ? std::string(src_ip) : std::string("0.0.0.0"),
            src_port,
            filename ? std::string(filename) : std::string(""),
            std::string(""),
            status ? std::string(status) : std::string("UNKNOWN")
        );
    }

    void Logger_LogGooseAnomaly(const char* action,const char* src_mod_mac, const char* target_ref, const char* reason) {
        HoneypotLogger::getInstance().logEvent(
            std::string("GOOSE"), 
            action ? std::string(action) : std::string("UNKNOWN"), 
            src_mod_mac ? std::string(src_mod_mac) : std::string("00:00:00:00:00:00"), 
            0, 
            target_ref ? std::string(target_ref) : std::string(""), 
            reason ? std::string(reason) : std::string(""), 
            std::string("DENIED")
        );
    }

    void Logger_LogEvent(const char* protocol, const char* action, const char* src_ip, int src_port, const char* target, const char* value, const char* status) {
        HoneypotLogger::getInstance().logEvent(
            protocol ? std::string(protocol) : std::string("UNKNOWN"),
            action ? std::string(action) : std::string("UNKNOWN"),
            src_ip ? std::string(src_ip) : std::string("0.0.0.0"),
            src_port,
            target ? std::string(target) : std::string(""),
            value ? std::string(value) : std::string(""),
            status ? std::string(status) : std::string("UNKNOWN")
        );
    }

    void Logger_LogNtpEvent(const char* action, const char* src_ip, int src_port, const char* raw_payload, int payload_len) {
        std::string payload_str(raw_payload, payload_len);
        std::string hex_payload = HoneypotLogger::getInstance().hexDump(payload_str);
        
        HoneypotLogger::getInstance().logEvent(
            std::string("NTP/PTP"),
            action ? std::string(action) : std::string("UNKNOWN"),
            src_ip ? std::string(src_ip) : std::string("0.0.0.0"),
            src_port,
            std::string("SYSTEM_TIME"),
            hex_payload,
            std::string("DENIED")
        );
    }
}
