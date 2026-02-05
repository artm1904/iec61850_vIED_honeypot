#include <libiec61850/iec61850_server.h>
#include <libiec61850/iec61850_model.h>
#include <libiec61850/hal_thread.h>

#include "open_server.h"
#include "iec61850_dynamic_model_extensions.h"
#include "iec61850_config_file_parser_extensions.h"
#include "iec61850_model_extensions.h"
#include "inputs_api.h"
#include "timestep_config.h"

#include "config_parser.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <time.h>
#include <math.h>

#include "XSWI.h"
#include "MMXU.h"

#define BUFFER_SIZE 1024

/*
ui_loop
	check_ui_requests:
		{"command": "open_breaker"}-> perform local operate
		{"command": "close_breaker"}-> perform local operate
		{"command": "reset_trip"} // maybe handled in UI logic instead

		{"command": "get_measurements"}
			Expected response format:
			{
			  "voltage_l1": 13.8, From MMXU
			  "voltage_l2": 13.7, From MMXU
			  "voltage_l3": 13.9, From MMXU
			  "current_l1": 125.5, From MMXU
			  "current_l2": 124.8, From MMXU
			  "current_l3": 126.2, From MMXU
			  "breaker_state": "CLOSED", From XCBR.Pos.stval
			  "trip_active": false -> need to be moddeled in PTRC or XCBR as cause of operate
			  "fault": false -> ncurrent Tr value (not moddeled in UI yet!)
			}
*/

typedef enum {
    JSON_TYPE_BOOLEAN,
    JSON_TYPE_INTEGER,
    JSON_TYPE_FLOAT
} JsonValueType;

typedef enum {
    BREAKER_INTERMEDIATE = 0,
    BREAKER_OPEN    = 1,    // 01
    BREAKER_CLOSED  = 2,    // 10
    BREAKER_UNKNOWN = 3
} BreakerState;

typedef struct JsonNode {
    char *name; // key name
    void *inst; // logical node instance to get the data from
    IedServer server;
    DataAttribute* DA_ref;
    JsonValueType type;
    struct JsonNode *next;
} JsonNode;

typedef struct {
    double voltage_l1;
    double voltage_l2;
    double voltage_l3;
    double current_l1;
    double current_l2;
    double current_l3;
    BreakerState breaker_state;
    int trip_active;
} RelayData;

static const char *socket_path = NULL;
static JsonNode *UIConfigList = NULL;

JsonNode* create_node(JsonNode **head, const char *name, JsonValueType type, IedServer server, DataAttribute* DA_ref);
void free_json_list(JsonNode *head);
char* to_json_string(JsonNode *head);

static void UI_connector_socket_Thread(void * parameter);


int init(OpenServerInstance *srv)
{
    IedModel *model;
    IedModel_extensions *model_ex;

    printf(" ui_connector module initialising\n");
    model = srv->Model;
    model_ex = srv->Model_ex;
    
    config_t config;
    
    /* Parse the config file */
    if (config_parse_file("./plugin/ui_connector.config", &config) != 0) {
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

    /* Iterate through all key-value pairs */
    printf("\n settings for %s \n", section->section);
    for (int i = 0; i < section->entry_count; i++) {
        //printf("  %s = ", section->entries[i].key);
         // known keys
        if(strcmp(section->entries[i].key,"socket") == 0)
        {
            if(socket_path != NULL)
            {
                printf("WARNING: socket path already set to: %s! this second socket path definition is ignored: %s \n",socket_path,config_get_value(section, "socket"));
                continue;
            }
            const char *tmpsocket = config_get_value(section, "socket");
            const int socketln = strlen(tmpsocket);
            if(socketln > 256) {
                printf("ERROR: invalid socket path\n");
                continue;
            }

            char *socket_path_t = malloc(socketln+1);
            strcpy(socket_path_t,tmpsocket);
            socket_path = socket_path_t;

            Thread thread = Thread_create((ThreadExecutionFunction)UI_connector_socket_Thread, NULL, true);
            Thread_start(thread);

            continue;
        }
        
        if(strncmp(section->entries[i].key,"swi",3) == 0) // SWI[index], publish state, accept commands
        {
            LogicalNodeClass *ln = getLNClass(model, model_ex, section->entries[i].values[0]);
            if (ln == NULL)
            {
                printf("ERROR: could not parse or find an LN entry with key: %s\n", section->entries[i].values[0]);
                continue; //if not, give up
            }
            XSWI *item = ln->instance;
            create_node(&UIConfigList,section->entries[i].key,JSON_TYPE_INTEGER,srv->server,item->Pos_stVal);
            continue;
        }
        if(strncmp(section->entries[i].key,"cbr",3) == 0) // CBR[index], publish state, accept commands
        {
            LogicalNodeClass *ln = getLNClass(model, model_ex, section->entries[i].values[0]);
            if (ln == NULL)
            {
                printf("ERROR: could not parse or find an LN entry with key: %s\n", section->entries[i].values[0]);
                continue; //if not, give up
            }
            XSWI *item = ln->instance;
            create_node(&UIConfigList,section->entries[i].key,JSON_TYPE_INTEGER,srv->server,item->Pos_stVal);
            continue;
        }
        if(strncmp(section->entries[i].key,"ctr",3) == 0) // CTR[index], publish value
        {
            LogicalNodeClass *ln = getLNClass(model, model_ex, section->entries[i].values[0]);
            if (ln == NULL)
            {
                printf("ERROR: could not parse or find an LN entry with key: %s\n", section->entries[i].values[0]);
                continue; //if not, give up
            }
            MMXU *item = ln->instance;
            create_node(&UIConfigList,section->entries[i].key,JSON_TYPE_FLOAT,srv->server,item->da_A);
            continue;
        }
        if(strncmp(section->entries[i].key,"vtr",3) == 0) // VTR[index], publish value
        {
            LogicalNodeClass *ln = getLNClass(model, model_ex, section->entries[i].values[0]);
            if (ln == NULL)
            {
                printf("ERROR: could not parse or find an LN entry with key: %s\n", section->entries[i].values[0]);
                continue; //if not, give up
            }
            MMXU *item = ln->instance;
            create_node(&UIConfigList,section->entries[i].key,JSON_TYPE_FLOAT,srv->server,item->da_V);
            continue;
        }
        if(strncmp(section->entries[i].key,"loc",3) == 0) // Loc[index], local/remote; publish state and allow switching
        {
            LogicalNodeClass *ln = getLNClass(model, model_ex, section->entries[i].values[0]);
            if (ln == NULL)
            {
                printf("ERROR: could not parse or find an LN entry with key: %s\n", section->entries[i].values[0]);
                continue; //if not, give up
            }
            continue;
        }
        if(strncmp(section->entries[i].key,"set",3) == 0) // Setting[index]_[Name], publish value, accept write
        {
            LogicalNodeClass *ln = getLNClass(model, model_ex, section->entries[i].values[0]);
            if (ln == NULL)
            {
                printf("ERROR: could not parse or find an LN entry with key: %s\n", section->entries[i].values[0]);
                continue; //if not, give up
            }
            if(section->entries[i].value_count > 1)
            {
                printf("INFO: DA for setting is %s\n",section->entries[i].values[1]);
                DataAttribute* attr = (DataAttribute*)ModelNode_getChild((ModelNode*)ln->parent, section->entries[i].values[1]);
                if (attr == NULL) {
                    printf("ERROR: failed to get DataAttribute for %s in %s\n",section->entries[i].values[1], section->entries[i].values[0]);
                    continue;  // Failed to get value
                }
                // Get the value
                MmsValue* mmsValue = IedServer_getAttributeValue(srv->server, attr);
                
                if (mmsValue == NULL) {
                    printf("ERROR: failed to get MmsValue for %s\n",section->entries[i].values[1]);
                    continue;  // Failed to get value
                }
                MmsType mmsType = MmsValue_getType(mmsValue);
                switch(mmsType)
                {
                    case MMS_BOOLEAN:
                        create_node(&UIConfigList,section->entries[i].key,JSON_TYPE_BOOLEAN,srv->server,attr);
                    break;
                    case MMS_INTEGER:
                    case MMS_UNSIGNED:
                    case MMS_BIT_STRING:
                        create_node(&UIConfigList,section->entries[i].key,JSON_TYPE_INTEGER,srv->server,attr);
                    break;
                    case MMS_FLOAT:
                        create_node(&UIConfigList,section->entries[i].key,JSON_TYPE_FLOAT,srv->server,attr);
                    break;
                    default:
                        printf("ERROR: unsupported MMS type for setting ref %s, type is %d", section->entries[i].values[1], mmsType);
                }
            }
            else
            {
                printf("ERROR: missing DA for setting %s\n",section->entries[i].key);
            }

            continue;
        }
    }

    config_free(&config);

    char * jj = to_json_string(UIConfigList);
    printf("%s\n",jj);
    free(jj);
    printf("ui_connector module initialised\n");
    return 0; // 0 means success
}



static int xasprintf(char **out, const char *fmt, ...)
{
    va_list ap;
    va_list ap_copy;
    int len;
    char *buf;
    if (!out || !fmt) return -1;

    *out = NULL;

    va_start(ap, fmt);
    va_copy(ap_copy, ap);

    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (len < 0) {
        va_end(ap_copy);
        return -1;
    }

    buf = malloc((size_t)len + 1);
    if (!buf) {
        va_end(ap_copy);
        return -1;
    }

    vsnprintf(buf, (size_t)len + 1, fmt, ap_copy);
    va_end(ap_copy);

    *out = buf;
    return len;
}


static void UI_connector_socket_Thread(void * parameter) {
    int server_fd, client_fd;
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];

    printf(" Starting ui_connector on socket %s\n", socket_path);
    
    /* Create socket */
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("ERROR: cannot create socket\n");
        return;
    }
    
    /* Remove existing socket file */
    unlink(socket_path);
    
    /* Bind socket */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("ERROR: cannot bind to path: %s\n", socket_path);
        close(server_fd);
        return;
    }
    
    /* Listen for connections */
    if (listen(server_fd, 1) < 0) {
        printf("ERROR: cannot listen on socket\n");
        close(server_fd);
        unlink(socket_path);
        return;
    }

    while(open_server_running())
    {
        printf("Waiting for client connection...\n");
        
        /* Accept connection (blocking) */
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            printf("ERROR: invalid client connetion\n");
            continue;
        }
        
        printf("Client connected!\n"); // only 1 client at a time is allowed
        
        /* Main command loop */
        while (open_server_running()) {
            ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
            
            if (bytes_read <= 0) {
                if (bytes_read == 0) {
                    printf("Client disconnected\n");
                } else {
                    printf("ERROR: read\n");
                }
                break;
            }
            
            buffer[bytes_read] = '\0';
            //printf("Received: %s", buffer);
            
            /* Process command and build response */ 
            char * response = NULL;        
            if (strstr(buffer, "get_measurements")) {
                response = to_json_string(UIConfigList);
            }
            else if (strstr(buffer, "open_breaker")) {
                // TODO implement opening of breaker/switch
                xasprintf(&response, "{\"status\":\"ok\",\"action\":\"breaker_opened\"}\n");
            }
            else if (strstr(buffer, "close_breaker")) {
                // TODO implement closing of breaker/switch
                xasprintf(&response, "{\"status\":\"ok\",\"action\":\"breaker_closed\"}\n");
            }
            else {
                xasprintf(&response, "{\"status\":\"error\",\"message\":\"unknown_command\"}\n");
            }

            /* Send response */
            ssize_t bytes_written = write(client_fd, response, strlen(response));
            free(response);
            if (bytes_written < 0) {
                printf("ERROR: write\n");
                break;
            }
            //printf("Sent: %s", response);
        }
        
        /* Cleanup */
        close(client_fd);
    }

    close(server_fd);
    unlink(socket_path);
    
    printf("Server shutdown\n");
    return;
}

/* Main function to convert linked list to JSON string */
char* to_json_string(JsonNode *head) {
    if (!head) {
        /* Empty list returns empty JSON object */
        char *result = malloc(3);
        if (result) strcpy(result, "{}");
        return result;
    }
    
    /* First pass: calculate required buffer size */
    size_t total_size = 2; /* For opening and closing braces */
    JsonNode *current = head;
    int count = 0;
    
    while (current) {
        /* Add size for "name": */
        total_size += strlen(current->name) + 4; /* quotes + colon + space */
        
        /* Add size for value */
        switch (current->type) {
            case JSON_TYPE_BOOLEAN:
                total_size += 5; /* "true" or "false" */
                break;
            case JSON_TYPE_INTEGER:
                total_size += 20; /* Max int digits */
                break;
            case JSON_TYPE_FLOAT:
                total_size += 30; /* Max float representation */
                break;
        }
        
        if (current->next) {
            total_size += 2; /* For ", " separator */
        }
        
        current = current->next;
        count++;
    }
    
    /* Allocate buffer */
    char *json = malloc(total_size + 1);
    if (!json) return NULL;
    
    /* Build JSON string */
    strcpy(json, "{");
    current = head;
    
    while (current) {
        /* Add name */
        strcat(json, "\"");
        strcat(json, current->name);
        strcat(json, "\": ");
        
        /* Add value based on type */
        char temp[100];
        MmsValue* mmsValue = IedServer_getAttributeValue(current->server, current->DA_ref);
        switch (current->type) {
            case JSON_TYPE_BOOLEAN:
                strcat(json, MmsValue_getBoolean(mmsValue) ? "true" : "false");
                break;
            case JSON_TYPE_INTEGER:
                sprintf(temp, "%d", MmsValue_toInt32(mmsValue));
                strcat(json, temp);
                break;
            case JSON_TYPE_FLOAT:
                sprintf(temp, "%g", MmsValue_toFloat(mmsValue));
                strcat(json, temp);
                break;
        }
        
        /* Add separator if not last element */
        if (current->next) {
            strcat(json, ", ");
        }
        
        current = current->next;
    }
    
    strcat(json, "}");
    return json;
}


JsonNode* create_node(JsonNode **head, const char *name, JsonValueType type, IedServer server, DataAttribute* DA_ref) {
    JsonNode *node = malloc(sizeof(JsonNode));
    if (!node) return NULL;
    
    node->name = malloc(strlen(name) + 1);
    if (!node->name) {
        free(node);
        return NULL;
    }
    strcpy(node->name, name);
    node->type = type;
    node->server = server;
    node->DA_ref = DA_ref;

    JsonNode *temp = *head;
    *head = node;
    node->next = temp;
    return node;
}

void free_json_list(JsonNode *head) {
    while (head) {
        JsonNode *temp = head;
        head = head->next;
        free(temp->name);
        free(temp);
    }
}
