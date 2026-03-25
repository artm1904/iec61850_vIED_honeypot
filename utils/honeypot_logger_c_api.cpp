#include "honeypot_logger_c_api.h"
#include "honeypot_logger.hpp"

extern "C" {
    void Logger_Init() {
        // T-Pot default path, adjust as needed in real docker env
        HoneypotLogger::getInstance().init("/var/log/tpot/vied_events.json");
    }

    void Logger_LogMmsAction(const char* action, const char* src_ip, int src_port, const char* target, const char* value, const char* status) {
        HoneypotLogger::getInstance().logEvent(
            "MMS", 
            action ? action : "UNKNOWN", 
            src_ip ? src_ip : "0.0.0.0", 
            src_port, 
            target ? target : "", 
            value ? value : "", 
            status ? status : "UNKNOWN"
        );
    }

    void Logger_LogFileAccess(const char* action, const char* src_ip, int src_port, const char* filename, const char* status) {
        HoneypotLogger::getInstance().logEvent(
            "MMS", 
            action ? action : "FILE_ACCESS",
            src_ip ? src_ip : "0.0.0.0",
            src_port,
            filename ? filename : "",
            "",
            status ? status : "UNKNOWN"
        );
    }

    void Logger_LogGooseAnomaly(const char* src_mod_mac, const char* target_ref, const char* reason) {
        HoneypotLogger::getInstance().logEvent(
            "GOOSE", "INJECT", src_mod_mac ? src_mod_mac : "00:00:00:00:00:00", 0, 
            target_ref ? target_ref : "", reason ? reason : "", "DENIED"
        );
    }
}
