/*
 *  open_server.c
 */

#include "open_server.h"
#include "LNParse.h"
#include "honeypot_logger_c_api.h"
#include "iec61850_config_file_parser_extensions.h"
#include "iec61850_dynamic_model_extensions.h"
#include "iec61850_model_extensions.h"
#include "inputs_api.h"
#include "timestep_config.h"
#include <string.h>

#include <libiec61850/hal_thread.h> /* for Thread_sleep() */
#include <libiec61850/mms_server.h>
#include <libiec61850/sv_publisher.h>
#include <libiec61850/iec61850_server.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h> // for getopt

#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libiec61850/hal_socket.h>

static int global_step = 0;
static int global_timestep_type = TIMESTEP_TYPE_LOCAL; // TIMESTEP_TYPE_REMOTE
static int running = 0;

#include <stdatomic.h>
#include <pthread.h>

atomic_int mms_req_cnt = 0;
atomic_int goose_req_cnt = 0;



// Мониторинг DoS атак через MMS, GOOSE протоколы
void* dos_monitor_thread(void* arg) {
    (void)arg;
    while(running) {
        Thread_sleep(1000); // 1 раз в секунду
        
        int mms_rate = atomic_exchange(&mms_req_cnt, 0);
        int goose_rate = atomic_exchange(&goose_req_cnt, 0);

        if (mms_rate > 20) { // A33-A34 
            char reason[64];
            snprintf(reason, sizeof(reason), "MMS DoS (Rate: %d req/s)", mms_rate);
            Logger_LogEvent("MMS", "DoS_ATTACK", "MULTIPLE", 0, "SYSTEM", "", reason);
        }
        
        if (goose_rate > 30) { // A31-A32
            char reason[64];
            snprintf(reason, sizeof(reason), "GOOSE/SV DoS Flood (Rate: %d pkts/s)", goose_rate);
            Logger_LogEvent("GOOSE", "DoS_ATTACK", "MULTIPLE", 0, "SYSTEM", "", reason);
        }
    }
    return NULL;
}

void* ntp_monitor_thread(void* arg) {
    (void)arg;
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("NTP socket creation failed");
        return NULL;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(123); // NTP

    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("NTP bind failed");
        close(sockfd);
        return NULL;
    }

    char buffer[1024];
    while(running) {
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&cliaddr, &len);
        if (n > 0) {
            char clientIp[64];
            inet_ntop(AF_INET, &(cliaddr.sin_addr), clientIp, INET_ADDRSTRLEN);
            Logger_LogEvent("NTP/PTP", "TIME_SPOOF_ATTACK_A3_A4", clientIp, ntohs(cliaddr.sin_port), "SYSTEM_TIME", "NTP_PAYLOAD", "DENIED");
        }
    }
    close(sockfd);
    return NULL;
}

static void
connectionHandler(IedServer self, ClientConnection connection, bool connected, void* parameter)
{
    if (connected) {
        atomic_fetch_add(&mms_req_cnt, 1);
    }
}

static MmsDataAccessError
mmsWriteHandler(DataAttribute* dataAttribute, MmsValue* value, ClientConnection connection, void* parameter)
{
    atomic_fetch_add(&mms_req_cnt, 1);
    
    char clientIp[64] = "UNKNOWN";
    if (connection) {
        const char *ip = ClientConnection_getPeerAddress(connection);
        if (ip) { strncpy(clientIp, ip, 63); clientIp[63] = '\0'; }
    }
    
    char objRef[128] = "";
    if (dataAttribute && dataAttribute->name) StringUtils_copyStringToBuffer(dataAttribute->name, objRef);

    char valStr[128] = "";
    if (value) MmsValue_printToBuffer(value, valStr, sizeof(valStr));

    const char* status = (strcmp(clientIp, "0.0.0.0") == 0) ? "AUTHORIZED" : "UNAUTHORIZED_ATTACK";  //All Write pretion is unauthorized, because in simulation we don't have real client ip
    Logger_LogMmsAction("WRITE", clientIp, 102, objRef, valStr, status);  // A9-A10 - Нарушитель решил осуществить подмену информации, передаваемой по MMS

    if (parameter) IedServer_updateAttributeValue((IedServer)parameter, dataAttribute, value);

    return DATA_ACCESS_ERROR_SUCCESS;
}

void attachWriteHandlersRecursively(IedServer server, ModelNode* node) {
    if (!node) return;
    if (node->modelType == DataObjectModelType) {
        IedServer_handleWriteAccessForDataObject(server, (DataObject*)node, IEC61850_FC_SP, mmsWriteHandler, server);
        IedServer_handleWriteAccessForDataObject(server, (DataObject*)node, IEC61850_FC_CF, mmsWriteHandler, server);
        IedServer_handleWriteAccessForDataObject(server, (DataObject*)node, IEC61850_FC_DC, mmsWriteHandler, server);
    }
    ModelNode* child = node->firstChild;
    while (child) {
        attachWriteHandlersRecursively(server, child);
        child = child->sibling;
    }
}

void IEC61850_server_timestep_next_step() {
  global_step++;
  // printf("step: %i\n",global_step);
}

void IEC61850_server_timestep_sync(int local) {
  while (local >= global_step)
    Thread_sleep(1);
}

int IEC61850_server_timestep_async(int local) {
  if (local == global_step) {
    Thread_sleep(1);
    return 1;
  } else {
    return 0;
  }
}

int IEC61850_server_timestep_type() { return global_timestep_type; }

void sigint_handler(int signalId) {
  printf("--- stopping server due to SIGINT ---\n\n");
  running = 0;
}

int open_server_running() { return running; }

static MmsError fileAccessHandler(void *parameter,
                                  MmsServerConnection connection,
                                  MmsFileServiceType service,
                                  const char *localFilename,
                                  const char *otherFilename) {
  printf("fileAccessHandler: service = %i, local-file: %s other-file: %s\n",
         service, localFilename, otherFilename);

  const char *actionName = "OTHER";
  if (service == MMS_FILE_ACCESS_TYPE_RENAME)
    actionName = "RENAME";
  else if (service == MMS_FILE_ACCESS_TYPE_DELETE)
    actionName = "DELETE";
  else if (service == MMS_FILE_ACCESS_TYPE_OBTAIN)
    actionName = "OBTAIN";
  else if (service == MMS_FILE_ACCESS_TYPE_OPEN)
    actionName = "OPEN";

  char clientIp[64] = "0.0.0.0";
  if (connection) {
    const char *ip = MmsServerConnection_getClientAddress(connection);
    if (ip) {
      strncpy(clientIp, ip, 63);
      clientIp[63] = '\0';
    }
  }

  const char *status = "DENIED";
  const char *status_allowed = "ALLOWED";
  
  // A13-A14, A17-A18 Detectors
  const char* ext = strrchr(localFilename, '.');
  if (ext != NULL) {
      if (strcasecmp(ext, ".bin") == 0 || strcasecmp(ext, ".elf") == 0 || 
          strcasecmp(ext, ".tar") == 0 || strcasecmp(ext, ".sh") == 0 || 
          strcasecmp(ext, ".so") == 0) {
          status = "FIRMWARE_REPLACEMENT_ATTEMPT_A17_A18";
          status_allowed = "FIRMWARE_REPLACEMENT_ATTEMPT_A17_A18";
      }
      else if (strcasecmp(ext, ".py") == 0 || strcasecmp(ext, ".js") == 0) {
          status = "APP_REPLACEMENT_ATTEMPT_A13_A14";
          status_allowed = "APP_REPLACEMENT_ATTEMPT_A13_A14";
      }
  }

  /* Don't allow client to rename files */
  if (service == MMS_FILE_ACCESS_TYPE_RENAME) {
    Logger_LogFileAccess(actionName, clientIp, 0, localFilename, status); //A9-A10 - Нарушитель решил осуществить подмену информации, передаваемой по MMS
    return MMS_ERROR_FILE_FILE_ACCESS_DENIED;
  }

  /* Don't allow client to delete files */
  if (service == MMS_FILE_ACCESS_TYPE_DELETE) {
    Logger_LogFileAccess(actionName, clientIp, 0, localFilename, status); //A9-A10 - Нарушитель решил осуществить подмену информации, передаваемой по MMS
    // if (strcmp(localFilename, "IEDSERVER.BIN") == 0)
    return MMS_ERROR_FILE_FILE_ACCESS_DENIED;
  }

  Logger_LogFileAccess("READ/WRITE/OTHER", clientIp, 0, localFilename, //A9-A10 - Нарушитель решил осуществить подмену информации, передаваемой по MMS
                       status_allowed);
  /* allow all other accesses */
  return MMS_ERROR_NONE;
}

int main(int argc, char **argv) {
  OpenServerInstance openServer;
  openServer.server = NULL;
  openServer.Model = NULL;
  // IedModel *iedModel_local = NULL;
  openServer.Model_ex = NULL;
  // IedModel_extensions *iedExtendedModel_local = NULL;
  openServer.allInputValues = NULL;
  openServer.SMVControlInstances = NULL;

  int port = 102;
  char *ethernetIfcID = NULL; // no default here
  char *ipAddress = NULL;
  char *cfgFile = NULL;
  char *extFile = NULL;
  char timestep_type = 0;

  // Flags to track if option is explicitly set
  int opt_e_set = 0, opt_p_set = 0, opt_c_set = 0, opt_x_set = 0, opt_t_set = 0;

  int opt;
  while ((opt = getopt(argc, argv, "e:p:i:c:x:t:")) != -1) {
    switch (opt) {
    case 'e':
      ethernetIfcID = optarg;
      opt_e_set = 1;
      break;
    case 'p':
      port = atoi(optarg);
      opt_p_set = 1;
      break;
    case 'i':
      ipAddress = optarg;
      break;
    case 'c':
      cfgFile = optarg;
      opt_c_set = 1;
      break;
    case 'x':
      extFile = optarg;
      opt_x_set = 1;
      break;
    case 't':
      timestep_type = optarg[0];
      opt_t_set = 1;
      break;
    default:
      fprintf(stderr,
              "Usage: %s [-e ethernet] [-p port] [-i ip] [-c cfgfile] [-x "
              "extfile] [-t L|R]\n",
              argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  // Backwards compatibility with positional arguments if options not set
  int pos_index = optind;
  if (!opt_e_set && argc > pos_index)
    ethernetIfcID = argv[pos_index++];
  if (!opt_p_set && argc > pos_index)
    port = atoi(argv[pos_index++]);
  if (!opt_c_set && argc > pos_index)
    cfgFile = argv[pos_index++];
  if (!opt_x_set && argc > pos_index)
    extFile = argv[pos_index++];
  if (!opt_t_set && argc > pos_index)
    timestep_type = argv[pos_index][0];

  // Use default for interface if still NULL
  if (!ethernetIfcID)
    ethernetIfcID = "lo";

  // Initialize Security Logger
  Logger_Init();

  if (cfgFile && extFile) {
    openServer.Model = ConfigFileParser_createModelFromConfigFileEx(cfgFile);
    openServer.Model_ex = ConfigFileParser_createModelFromConfigFileEx_inputs(
        extFile, openServer.Model);

    if (openServer.Model == NULL || openServer.Model_ex == NULL) {
      printf("Parsing dynamic config failed! Exit.\n");
      exit(-1);
    }
  } else {
    printf("No valid model provided! Exit.\n");
    exit(-1);
  }

  if (timestep_type == 'L' || timestep_type == 0) {
    global_timestep_type = TIMESTEP_TYPE_LOCAL;
    timestep_type = 'L';
  } else if (timestep_type == 'R')
    global_timestep_type = TIMESTEP_TYPE_REMOTE;
  else {
    printf("Invalid timestep type! Use 'L' or 'R'.\n");
    exit(-1);
  }

  openServer.server = IedServer_create(openServer.Model);

  printf("Using interface: %s\n", ethernetIfcID);
  if (ipAddress) {
    printf("Using IP address: %s\n", ipAddress);
    IedServer_setLocalIpAddress(openServer.server, ipAddress);
  }
  printf("Using port: %d\n", port);

  // Catch connections for DoS monitor
  IedServer_setConnectionIndicationHandler(openServer.server, connectionHandler, NULL);

  // By default we deny writing to SP elements, unless we have explicitly
  // installed a write handler inside the LN init. example: PTOC installs this
  // for StrVal
  IedServer_setWriteAccessPolicy(openServer.server, IEC61850_FC_SP, ACCESS_POLICY_ALLOW);  // Разрешаем запись данного типа переменных 
  IedServer_setWriteAccessPolicy(openServer.server, IEC61850_FC_CF, ACCESS_POLICY_ALLOW);  // Разрешаем запись данного типа переменных 
  IedServer_setWriteAccessPolicy(openServer.server, IEC61850_FC_DC, ACCESS_POLICY_ALLOW);  // Разрешаем запись данного типа переменных 

  // HONEYPOT: Attach write handlers to intercept and log all allowed writes
  if (openServer.Model && openServer.Model->firstChild) {
      attachWriteHandlersRecursively(openServer.server, (ModelNode*)openServer.Model->firstChild);
  }

  GooseReceiver GSEreceiver = GooseReceiver_create();
  SVReceiver SMVreceiver = SVReceiver_create();

  /* set GOOSE interface for all GOOSE publishers (GCBs) */
  IedServer_setGooseInterfaceId(openServer.server, ethernetIfcID);
  // goose subscriber
  GooseReceiver_setInterfaceId(GSEreceiver, ethernetIfcID);
  // smv subscriber
  SVReceiver_setInterfaceId(SMVreceiver, ethernetIfcID);

  // subscribe to datasets and local DA's based on iput/extRef, and generate one
  // list with all inputValues
  openServer.allInputValues =
      subscribeToGOOSEInputs(openServer.Model_ex, GSEreceiver);
  LinkedList temp = LinkedList_getLastElement(openServer.allInputValues);
  temp->next = subscribeToSMVInputs(openServer.Model_ex, SMVreceiver);
  temp = LinkedList_getLastElement(temp);
  temp->next = subscribeToLocalDAInputs(openServer.server, openServer.Model_ex,
                                        openServer.Model);

  // start subscribers
  GooseReceiver_start(GSEreceiver);
  SVReceiver_start(SMVreceiver);

  if (GooseReceiver_isRunning(GSEreceiver) ||
      SVReceiver_isRunning(SMVreceiver)) {
    printf("receivers working...\n");
  } else {
    printf("WARNING: no receivers are running\n");
  }

  /* MMS server will be instructed to start listening to client connections. */
  IedServer_start(openServer.server, port);
  running = 1;

  pthread_t dos_thread;
  pthread_create(&dos_thread, NULL, dos_monitor_thread, NULL);

  pthread_t ntp_thread;
  pthread_create(&ntp_thread, NULL, ntp_monitor_thread, NULL);

  if (!IedServer_isRunning(openServer.server)) {
    printf("Starting server failed! Exit.\n");
    IedServer_destroy(openServer.server);
    exit(-1);
  }

  // call initializers for sampled value control blocks and start publishing
  openServer.SMVControlInstances =
      attachSMV(openServer.server, openServer.Model, openServer.allInputValues,
                ethernetIfcID);

  // call all initializers for logical nodes in the model
  attachLogicalNodes(openServer.server, openServer.Model, openServer.Model_ex,
                     openServer.allInputValues);

  /* Start GOOSE publishing */
  IedServer_enableGoosePublishing(openServer.server);

  /* PLUGIN SYSTEM */
  // load all .so in plugin folder, and call init
  // plugins are allowed to call exported functions from main executable

  printf("\n--- loading plugins ---\n");
  DIR *d;
  struct dirent *dir;
  d = opendir("./plugin");
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      void *so_handle = NULL;
      lib_init_func init_func = NULL;

      size_t namelen = strlen(dir->d_name);

      if (dir->d_type != DT_REG || // only regular files
          strcmp(".", dir->d_name) == 0 ||
          strcmp("..", dir->d_name) == 0 || // ignore . and ..
          namelen < 4 || // ensure namelength is large enough to be calles ?.so
          strcmp(".so", dir->d_name + namelen - 3) !=
              0) // check if name ends with .so
      {
        continue;
      }
      printf("loading plugin: %s\n", dir->d_name);

      char *fullname = malloc(namelen + 10);
      strcpy(fullname, "./plugin/");
      strncat(fullname, dir->d_name, namelen + 10);
      so_handle = dlopen(fullname, RTLD_NOW | RTLD_GLOBAL);
      free(fullname);

      if (so_handle == NULL) {
        printf("ERROR: Unable to open lib: %s\n", dlerror());
        continue;
      }
      init_func = dlsym(so_handle, "init");

      if (init_func == NULL) {
        printf("ERROR: Unable to get symbol\n");
        continue;
      }
      if (init_func(&openServer) != 0) {
        printf("ERROR: could not succesfully run init of plugin: %s\n",
               dir->d_name);
      }
      printf("\n");
    }
    closedir(d);
  }
  printf("--- loading plugins finished ---\n\n");

  IedServer_setFilestoreBasepath(openServer.server, "./vmd-filestore/");
  /* Set a callback handler to control file accesses */
  MmsServer_installFileAccessHandler(IedServer_getMmsServer(openServer.server),
                                     fileAccessHandler, NULL);

  signal(SIGINT, sigint_handler);
  while (running) {
    Thread_sleep(1000);
    fflush(stdout); // ensure logging is flushed every second
  }

  GooseReceiver_stop(GSEreceiver);

  GooseReceiver_destroy(GSEreceiver);

  SVReceiver_stop(SMVreceiver);
  /* Cleanup and free resources */
  SVReceiver_destroy(SMVreceiver);
  /* stop MMS server - close TCP server socket and all client sockets */
  IedServer_stop(openServer.server);
  /* Cleanup - free all resources */
  IedServer_destroy(openServer.server);

} /* main() */
