#include "iec61850_model_extensions.h"
#include "inputs_api.h"

#define CILO_MAX_INPUT 16

typedef struct sCILO
{
  IedServer server;
  bool EnaOpn;
  bool EnaCls;
  DataAttribute *EnaOpn_DA;
  void *EnaOpn_callback;
  DataAttribute *EnaCls_DA;
  void *EnaCls_callback;
} CILO;

bool ParsePos(const MmsValue *pos)
{
  MmsType type = MmsValue_getType(pos);
  if(type == MMS_BOOLEAN){
    return MmsValue_getBoolean(pos);
  }
  if(type == MMS_BIT_STRING){
    Dbpos dbpos = Dbpos_fromMmsValue(pos);
    if (dbpos == DBPOS_OFF) // XCBR/XSWI is open, so its safe
    {
      return false;
    }
    else // If XCBR is moving, or closed, assumen its closed(i.e not safe)
    {
      return true;
    }
  }
  printf("ERROR: CILO Cannot parse position of type: %d, state set to 'false'\n", type);
  return false;
}

void SetEnaOpn(CILO * inst,bool state)
{
  printf("CILO.SetEnaOpn = %d\n", state);
  MmsValue *open = MmsValue_newBoolean(state);  // false = XSWI/XCBR cannot open, true = XSWI/XCBR can open

  IedServer_updateAttributeValue(inst->server, inst->EnaOpn_DA, open);
  InputValueHandleExtensionCallbacks(inst->EnaOpn_callback); // update the associated callbacks with this Data Element

  MmsValue_delete(open);
  inst->EnaOpn = state;
}

void SetEnaCls(CILO * inst,bool state)
{
  printf("CILO.SetEnaCls = %d\n", state);
  MmsValue *close = MmsValue_newBoolean(state); // fasle = XSWI/XCBR cannot open, true = XSWI/XCBR can open

  IedServer_updateAttributeValue(inst->server, inst->EnaCls_DA, close);
  InputValueHandleExtensionCallbacks(inst->EnaCls_callback); // update the associated callbacks with this Data Element

  MmsValue_delete(close);
  inst->EnaCls = state;
}

// receive status from any circuit breaker
void CILO_not_callback(InputEntry *extRef)
{
  CILO *inst = extRef->callBackParam;

  if (extRef->value != NULL && inst != NULL)
  { 
    bool desired_state = !ParsePos(extRef->value);; // processing of state, in this case only NOT
    if(desired_state != inst->EnaOpn)
      SetEnaOpn(inst,desired_state); // invert state, so an DBPOS_OFF switch(false) will set EnaOpn
    if(desired_state != inst->EnaCls)
      SetEnaCls(inst,desired_state); // invert state, so an DBPOS_OFF switch(false) will set EnaCls
  }
}

void CILO_and_callback(InputEntry *extRef) // all switch = true, will result in EnaOpn+EnaCls = true, 
                                           // any switch = false, will result in EnaOpn+EnaCls = false
{
  CILO *inst = extRef->callBackParam;
  if (extRef->value != NULL && inst != NULL) {
    
  }
}

void CILO_nand_callback(InputEntry *extRef) // all switch = true, will result in EnaOpn+EnaCls = false,
                                            // any switch false, will result in EnaOpn+EnaCls = true
{
  CILO *inst = extRef->callBackParam;
  if (extRef->value != NULL && inst != NULL) {
    
  }
}

void CILO_or_callback(InputEntry *extRef) // any switch = true will result in EnaOpn+EnaCls = true, 
                                          // all switch = false, will result in EnaOpn+EnaCls = false
{
  CILO *inst = extRef->callBackParam;
  if (extRef->value != NULL && inst != NULL) {
    
  }
}

void CILO_nor_callback(InputEntry *extRef) // any switch = true will result in EnaOpn+EnaCls = false
                                           // all switch = false, will result in EnaOpn+EnaCls = true
{
  CILO *inst = extRef->callBackParam;
  if (extRef->value != NULL && inst != NULL) {
    
  }
}


void * CILO_init(IedServer server, LogicalNode *ln, Input *input, LinkedList allInputValues)
{
  CILO *inst = (CILO *)malloc(sizeof(CILO)); // create new instance with MALLOC

  inst->server = server;
  inst->EnaOpn = true;
  inst->EnaCls = true;
  inst->EnaOpn_DA = (DataAttribute *)ModelNode_getChild((ModelNode *)ln, "EnaOpn.stVal");
  inst->EnaOpn_callback = _findAttributeValueEx(inst->EnaOpn_DA, allInputValues);
  inst->EnaCls_DA = (DataAttribute *)ModelNode_getChild((ModelNode *)ln, "EnaCls.stVal");
  inst->EnaCls_callback = _findAttributeValueEx(inst->EnaCls_DA, allInputValues);

  // find extref for the last SMV, using the intaddr
  if (input != NULL)
  {
    InputEntry *extRef = input->extRefs;

    while (extRef != NULL)
    {
      // receive status of associated XCBR
      if (strcmp(extRef->intAddr, "stval") == 0) // direct logic, inverse of value is output
      {
        extRef->callBack = (callBackFunction)CILO_not_callback;
        extRef->callBackParam = inst;
      }

      if (strncmp(extRef->intAddr, "in_or_",6) == 0)
      {
        extRef->callBack = (callBackFunction)CILO_or_callback;
        extRef->callBackParam = inst;
      }
      if (strncmp(extRef->intAddr, "in_nor_",7) == 0)
      {
        extRef->callBack = (callBackFunction)CILO_nor_callback;
        extRef->callBackParam = inst;
      }
      if (strncmp(extRef->intAddr, "in_and_",7) == 0)
      {
        extRef->callBack = (callBackFunction)CILO_and_callback;
        extRef->callBackParam = inst;
      }
      if (strncmp(extRef->intAddr, "in_nand_",8) == 0)
      {
        extRef->callBack = (callBackFunction)CILO_nand_callback;
        extRef->callBackParam = inst;
      }

      extRef = extRef->sibling;
    }
  }
  return inst;
}
