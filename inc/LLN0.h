#ifndef LLN0_H_
#define LLN0_H_

#include "iec61850_model_extensions.h"
#include "inputs_api.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct sLLN0
{
  IedServer server;
  Input *input;
  DataAttribute * Loc_stVal;
  DataAttribute * Loc_t;
  void * Loc_stVal_callback;

} LLN0;

void LLN0_SetLoc (LLN0 *inst, bool Local);

void *LLN0_init(IedServer server, LogicalNode* ln, Input *input, LinkedList allInputValues);

#ifdef __cplusplus
}
#endif


#endif /* LLN0_H_ */