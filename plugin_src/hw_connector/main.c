#include <libiec61850/iec61850_server.h>
#include <libiec61850/iec61850_model.h>
#include <libiec61850/hal_thread.h>

#include "open_server.h"
#include "iec61850_dynamic_model_extensions.h"
#include "iec61850_config_file_parser_extensions.h"
#include "iec61850_model_extensions.h"
#include "inputs_api.h"
#include "timestep_config.h"
#include "LNParse.h"
#include "XSWI.h"
#include "TCTR.h"
#include "TVTR.h"
#include "config_parser.h"
#include <stdio.h>
#include <string.h>


// SOCKET example code
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>

#define BUFFER_SIZE 4096
#define LINE_BUFFER_SIZE 8192

typedef struct sHwConfig
{
    int hwindex;
    int socket;
    void *inst;
    struct sHwConfig *sibling;
} HwConfig;

HwConfig *HwConfigList_head = NULL;

typedef struct {
    int sockfd;
    volatile int *shutdown_flag;
} thread_args_t;

int initSocket(const char *sock_path);
int send_cmd(int sockfd, char * send_buf);

// socket example code end

// check ied-name, for config-entry
// connect to socket based on config
// connect cbr callback to xcbr/xswi and io-index based on config
// receive switch-status events, and modify respective stval(ref in config)
// when an operate-signal is send, send set io command over socket, based on config
// receive transformer-data and write it into CTR/VTR elements
//
// possible timestep call from socket to all clients?(to pace and sync the ieds?)
// possible dsp-override: if so, when a dsp-processing call is made, we just provide the rms-value the sine was calced from in the first place
//
//     if cmd[0] == "SET" and len(cmd) == 3:    ch = int(cmd[1]) state_val = cmd[2]
//   elif cmd[0] == "GET" and len(cmd) == 2:  ch = int(cmd[1])
//   elif cmd[0] == "GETDATA":

void XSWIcallback(void *inst, bool state)
{
    char buffer[64];
    XSWI *instance = inst;
    HwConfig *conf = instance->config;
    sprintf(buffer, "SET %d %d",conf->hwindex, state);
    send_cmd(conf->socket, buffer);
}

void * getInstViaHwIndex(int index)
{
    HwConfig *hwconf = HwConfigList_head;
    while(hwconf)
    {
        if(hwconf->hwindex == index)
        {
            return hwconf->inst;
        }
        hwconf = hwconf->sibling;
    }
    return NULL;
}

int init(OpenServerInstance *srv)
{
    IedModel *model;
    IedModel_extensions *model_ex;

    printf(" hw_connector module initialising\n");
    model = srv->Model;
    model_ex = srv->Model_ex;
    
    config_t config;
    
    /* Parse the config file */
    if (config_parse_file("./plugin/hw_connector.config", &config) != 0) {
        printf("ERROR: Failed to parse config file\n");
        return 1;
    }
    
    /* Find a specific device section */
    config_section_t *section = config_find_section(&config, model->name);
    
    if (!section) {
        printf("ERROR: Device '%s' not found in config\n", model->name);
        config_free(&config);
        return 1;
    }

    const char *socket_path = config_get_value(section, "socket");
    int socket = initSocket(socket_path);
    if(socket == 0)
    {
        printf("ERROR: issue while opening socket: %s\n", socket_path);
    }

    /* Iterate through all key-value pairs */
    printf("\n settings for %s \n", section->section);
    for (int i = 0; i < section->entry_count; i++) {
        //printf("  %s = ", section->entries[i].key);
         // known keys
        if(strcmp(section->entries[i].key,"socket") == 0)
        {
            printf("socket found\n");
            continue;
        }
        //if not a known key, try it as an object-reference
        LogicalNodeClass *ln = getLNClass(model, model_ex, section->entries[i].key);
        if (ln == NULL)
        {
            printf("ERROR: could not parse or find an LN entry with key: %s\n", section->entries[i].key);
            continue; //if not, give up
        }
        if(strcmp(ln->lnClass,"XSWI") == 0)
        {
            if (section->entries[i].value_count != 1) {
                printf("ERROR: XSWI: incorrect value format. should only be 1 number\n");
                continue;
            }
            XSWI *item = ln->instance;
            HwConfig *conf = (HwConfig *)malloc(sizeof(HwConfig));
            conf->hwindex = (int)strtol(section->entries[i].values[0], NULL, 10);
            conf->socket = socket;
            conf->inst = item;
            //place conf in linked list
            conf->sibling = HwConfigList_head;
            HwConfigList_head = conf;
            //
            item->config = conf;
            setXSWI_Callback(item, XSWIcallback);
            printf("XSWI: set callback and hw index to %d\n", conf->hwindex);
        }
        if(strcmp(ln->lnClass,"XCBR") == 0)
        {
            if (section->entries[i].value_count != 1) {
                printf("ERROR: XCBR: incorrect value format. should only be 1 number\n");
                continue;
            }
            XSWI *item = ln->instance;
            HwConfig *conf = (HwConfig *)malloc(sizeof(HwConfig));
            conf->hwindex = (int)strtol(section->entries[i].values[0], NULL, 10);
            conf->socket = socket;
            conf->inst = item;
            //place conf in linked list
            conf->sibling = HwConfigList_head;
            HwConfigList_head = conf;
            //
            item->config = conf;
            setXSWI_Callback(item, XSWIcallback);
            printf("XCBR: set callback and hw index to %d\n", conf->hwindex);
        }
        if(strcmp(ln->lnClass,"TCTR") == 0)
        {
            TCTR *item = ln->instance;
            if (section->entries[i].value_count == 1) {
                printf("TCTR: %s\n", section->entries[i].values[0]);
            }
        }
        if(strcmp(ln->lnClass,"TVTR") == 0)
        {
            TVTR *item = ln->instance;
            if (section->entries[i].value_count == 1) {
                printf("TVTR: %s\n", section->entries[i].values[0]);
            }
        }
    }

    config_free(&config);


    printf("hw_connector module initialised\n");
    return 0; // 0 means success
}


void *receiver_thread(void *arg) {
    bool shutdown_flag = false;
    thread_args_t *args = (thread_args_t *)arg;
    int sockfd = args->sockfd;
    char buffer[BUFFER_SIZE];
    char line_buffer[LINE_BUFFER_SIZE] = {0};
    int line_pos = 0;
    
    while (open_server_running() && !shutdown_flag) {
        ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000); // 10ms
                continue;
            }
            if (!shutdown_flag) {
                printf("\n[Receiver error: %s]\n", strerror(errno));
            }
            break;
        }
        
        if (n == 0) {
            printf("\n[Server closed connection]\n");
            shutdown_flag = 1;
            break;
        }
        
        buffer[n] = '\0';
        
        // Add to line buffer and process complete lines
        for (ssize_t i = 0; i < n; i++) {
            if (buffer[i] == '\n') {
                line_buffer[line_pos] = '\0';
                
                // Trim whitespace
                char *line = line_buffer;
                while (*line == ' ' || *line == '\t' || *line == '\r') line++;
                
                if (*line != '\0') {
                    // Check if it's a broadcast event
                    if (strncmp(line, "EVENT ", 6) == 0) {
                        char *event_data = line + 6;
                        //printf("\n[BROADCAST] %s\n", event_data);
                        // Distribute event to XSWI/XCBR/TVTR/TCTR
                        if(strncmp(event_data, "DATA", 4) == 0){
                            printf("recv: %s\n", &event_data[5]); //Avalue,value,... Sbyte,byte,... A=analog value, S=shortcitcuit yes/no        A0,1,2,3,4,5,6,7,8,9,10,11 S01,02,03,04,05,06
                        }
                        if(strncmp(event_data, "IO", 2) == 0){
                            char * endp;
                            printf("recv: %s\n", &event_data[3]);//{channel} {position}
                            int index = strtol(&event_data[3],&endp,10);
                            // look up XSWI, based on index
                            XSWI * instance = getInstViaHwIndex(index);
                            if(instance != NULL)
                            {                                
                                if(index < 10)
                                {
                                    int state = strtol(endp,NULL,10);
                                    if(state == 00)
                                    {
                                        XSWI_change_switch(instance, DBPOS_INTERMEDIATE_STATE);
                                    }
                                    if(state == 01)
                                    {
                                        XSWI_change_switch(instance, DBPOS_OFF);
                                    }
                                    if(state == 10)
                                    {
                                        XSWI_change_switch(instance, DBPOS_ON);
                                    }
                                }
                                else
                                {
                                    if(endp[1] == 'F')
                                    {
                                        XSWI_change_switch(instance, DBPOS_OFF);
                                    }
                                    if(endp[1] == 'T')
                                    {
                                        XSWI_change_switch(instance, DBPOS_ON);
                                    }
                                }
                            }
                            else
                            { 
                                printf("ERROR: could not find XSWI instance for hwindex: %d\n", index);
                            }
                        }
                    } else {
                        printf("\n[RESPONSE] %s\n NOT IMPLEMENTED YET\n", line);
                        
                    }
                    fflush(stdout);
                }
                
                line_pos = 0;
            } else {
                if (line_pos < LINE_BUFFER_SIZE - 1) {
                    line_buffer[line_pos++] = buffer[i];
                }
            }
        }
    }
    close(sockfd);
    return NULL;
}

int initSocket(const char *sock_path) {
    
    // Create socket
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 0;
    }
    
    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; // 500ms
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return 0;
    }
    
    // Connect to Unix socket
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("ERROR: Failed to connect to %s: %s\n", sock_path, strerror(errno));
        close(sockfd);
        return 0;
    }
    
    //printf("Connected to %s\n", sock_path);
    //printf("\nCommands:\n");
    //printf("  SET <channel> <value>    - Set channel state\n");
    //printf("  GET <channel>            - Get current event state for channel\n");
    //printf("  GETDATA                  - Get current data message\n");
    //printf("  quit                     - Exit program\n");
    //printf("\nBroadcast events will be displayed automatically as [BROADCAST]\n");
    //printf("------------------------------------------------------------\n");
    
    // Start receiver thread
    thread_args_t thread_args = {sockfd};
    Thread thread = Thread_create((ThreadExecutionFunction)receiver_thread, &thread_args, true);
    Thread_start(thread);
        
    return sockfd;
}

int send_cmd(int sockfd, char * send_buf)
{
    // Send command with newline
    ssize_t sent = send(sockfd, send_buf, strlen(send_buf), 0);
    if (sent < 0) {
        printf("[Send error: %s]\n", strerror(errno));
    }
}