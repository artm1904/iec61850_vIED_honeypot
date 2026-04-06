#ifndef HONEYPOT_LOGGER_C_API_H
#define HONEYPOT_LOGGER_C_API_H

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the logger */
void Logger_Init();

/* Log an MMS action */
void Logger_LogMmsAction(const char* action, const char* src_ip, int src_port, const char* target, const char* value, const char* status);

/* Log a file access action (MMS) */
void Logger_LogFileAccess(const char* action, const char* src_ip, int src_port, const char* filename, const char* status);

/* Log a GOOSE anomaly (e.g., injection, parsing error) */
void Logger_LogGooseAnomaly(const char* action, const char* src_mod_mac, const char* target_ref, const char* reason);

/* Generic logger function for DoS and related attacks */
void Logger_LogEvent(const char* protocol, const char* action, const char* src_ip, int src_port, const char* target, const char* value, const char* status);

/* Log NTP/PTP events converting raw payload to Hex Dump */
void Logger_LogNtpEvent(const char* action, const char* src_ip, int src_port, const char* raw_payload, int payload_len);

#ifdef __cplusplus
}
#endif

#endif // HONEYPOT_LOGGER_C_API_H
