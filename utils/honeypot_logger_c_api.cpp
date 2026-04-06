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
            "MMS", 
            action ? action : "UNKNOWN", 
            src_ip ? src_ip : "0.0.0.0", 
            src_port, 
            target ? target : "", 
            value ? value : "", 
            status ? status : "UNKNOWN"
        );
    }

    // A9 - Нарушитель решил осуществить подмену информации, передаваемой по MMS, используя ПО, доступное в открытом доступе и/или самостоятельно разработанное ПО
    // A10 - Нарушитель подключится к шине станции и отправит некорректные данные по MMS, используя ПО, доступное в открытом доступе и/или самостоятельно разработанное ПО
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


    // A23 - Нарушитель, решил осуществить подмену информации, передаваемую по GOOSE, используя ПО, доступное в открытом доступе и/или самостоятельно разработанное ПО
    // A24 - Нарушитель подключится к шине станции и отправит некорректные данные по GOOSE, используя ПО, доступное в открытом доступе и/или самостоятельно разработанное ПО
    void Logger_LogGooseAnomaly(const char* action,const char* src_mod_mac, const char* target_ref, const char* reason) {
        HoneypotLogger::getInstance().logEvent(
            "GOOSE", action ? action : "UNKNOWN", src_mod_mac ? src_mod_mac : "00:00:00:00:00:00", 0, 
            target_ref ? target_ref : "", reason ? reason : "", "DENIED"
        );
    }


    // А31-А32 Нарушитель решил, физически подключившись к шине станции, вызвать отказ в обслуживании ИЭУ вследствие DoS по GOOSE, 
    // используя общедоступное и/или самостоятельно разработанное ПО
    // A33-A34 Нарушитель решил, физически подключившись к шине станции, вызвать отказ в обслуживании ИЭУ вследствие DoS по MMS, 
    // используя общедоступное и/или самостоятельно разработанное ПО
    void Logger_LogEvent(const char* protocol, const char* action, const char* src_ip, int src_port, const char* target, const char* value, const char* status) {
        HoneypotLogger::getInstance().logEvent(
            protocol ? protocol : "UNKNOWN",
            action ? action : "UNKNOWN",
            src_ip ? src_ip : "0.0.0.0",
            src_port,
            target ? target : "",
            value ? value : "",
            status ? status : "UNKNOWN"
        );
    }
}
