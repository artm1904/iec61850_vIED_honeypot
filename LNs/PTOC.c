#include "iec61850_model_extensions.h"
#include "inputs_api.h"
#include <libiec61850/hal_thread.h>
// #include "../static_model.h"
#include "PTOC.h"
#include "dsp.h"
#include <time.h>
#include <math.h>

//
// PTOC : time over current protection; will trip after set time-curve when current is too high
//
typedef struct sPTOC
{
  IedServer server;
  DataAttribute *Op_general;
  void *Op_general_callback;
  Input *input;

  bool trip;

  msSinceEpoch prevTime;
  DSP *dspI;

  float StrVal;        // Pickup current
  float TmMult;        // Time multiplier

  float MinOpTmms;     // Minimum operate time (ms)
  float MaxOpTmms;     // Maximum operate time (ms)
  float OpDlTmms;      // Additional operate delay (ms)
  float RsDlTmms;      // Reset delay (ms)

  float progress[4];      // Trip integration state (0…1)
  float reset_timer[4];   // Time spent below pickup (ms)
} PTOC;

typedef enum {
  PTOC_NO_CHANGE,
  PTOC_TRIP,
  PTOC_TRIP_RESET
} PTOC_Result;

PTOC_Result PTOC_Update_algorithm(PTOC *ptoc, int channel, float I, float delta_t_ms)
{
    if (I > ptoc->StrVal)
    {
        ptoc->reset_timer[channel] = 0.0f;  // Cancel any pending reset

        float M = I / ptoc->StrVal;
        if (M < 1.01f) M = 1.01f;

        // IEC Standard Inverse curve (seconds)
        float t_curve_sec = ptoc->TmMult * (0.14f / (powf(M, 0.02f) - 1.0f));

        // Convert to milliseconds
        float t_operate_ms = t_curve_sec * 1000.0f;

        // Add definite operate delay
        t_operate_ms += ptoc->OpDlTmms;

        // Enforce min/max limits
        if (t_operate_ms < ptoc->MinOpTmms) t_operate_ms = ptoc->MinOpTmms;
        if (t_operate_ms > ptoc->MaxOpTmms) t_operate_ms = ptoc->MaxOpTmms;

        // Integrate toward trip
        ptoc->progress[channel] += delta_t_ms / t_operate_ms;

        if (ptoc->progress[channel] >= 1.0f)
        {
          return PTOC_TRIP;
        }
    }
    else
    {
        // Below pickup — start reset timing
        ptoc->reset_timer[channel] += delta_t_ms;

        if (ptoc->reset_timer[channel] >= ptoc->RsDlTmms)
        {
          ptoc->progress[channel] = 0.0f;
          ptoc->reset_timer[channel] = 0.0f;
          return PTOC_TRIP_RESET;
        }
    }
    return PTOC_NO_CHANGE;
}

// callback when SMV is received
void PTOC_callback_SMV(void *ptoc_inst)
{
  PTOC *ptoc = ptoc_inst;
  msSinceEpoch time = Hal_getTimeInMs();
  msSinceEpoch delta_t = time - ptoc->prevTime;
  ptoc->prevTime = time;

  bool local_trip = false;
  bool local_trip_reset = false;
  for(int i=0; i < 4; i++) // only read on amps.
  {
    float current =  DSP_get_phs(ptoc->dspI, i); // get absolute current from dsp
    PTOC_Result result = PTOC_Update_algorithm(ptoc, i, current, (float)delta_t);
    if(result == PTOC_TRIP)
    {
      local_trip = true;
    }
    if(result == PTOC_TRIP_RESET)
    {
      local_trip_reset = true;
    }
  }

  if(local_trip == true) // if one of the phases tripped
  {
    if(ptoc->trip != true) // and we were not already tripped
    {
      printf("PTOC: treshold reached by time overcurrent\n");
      MmsValue *tripValue = MmsValue_newBoolean(true);
      IedServer_updateAttributeValue(ptoc->server, ptoc->Op_general, tripValue);
      InputValueHandleExtensionCallbacks(ptoc->Op_general_callback); // update the associated callbacks with this Data Element
      MmsValue_delete(tripValue);
    }
    ptoc->trip = true;
  }
  else // if we did not have a trip on any phase
  {
    if(local_trip_reset == true) // then check if we maybe have a reset trip event
    {
      if (ptoc->trip == true)
      {
        printf("PTOC: treshold NOT reached anymore, fault reset\n");
        MmsValue *tripValue = MmsValue_newBoolean(false);
        IedServer_updateAttributeValue(ptoc->server, ptoc->Op_general, tripValue);
        InputValueHandleExtensionCallbacks(ptoc->Op_general_callback); // update the associated callbacks with this Data Element
        MmsValue_delete(tripValue);
      }
      ptoc->trip = false;
    }
  }
}

void * PTOC_init(IedServer server, LogicalNode *ln, Input *input, LinkedList allInputValues)
{
  PTOC *inst = (PTOC *)malloc(sizeof(PTOC)); // create new instance with MALLOC
  inst->server = server;
  inst->trip = false;
  inst->Op_general = (DataAttribute *)ModelNode_getChild((ModelNode *)ln, "Op.general"); // the node to operate on
  inst->Op_general_callback = _findAttributeValueEx(inst->Op_general, allInputValues);
  inst->input = input;
  inst->dspI = NULL;

  IecDataPoint dataPoints[8] = {
      {"TmACrv.setCharact", IEC_TYPE_INT32},// 0 Operating curve type (IEC Standard Inverse), value is ignored
      {"StrVal.setMag.f", IEC_TYPE_FLOAT},  // 1 Start value
      {"TmMult.setMag.f", IEC_TYPE_FLOAT},  // 2 Time dial multiplier
      {"MinOpTmms.setVal", IEC_TYPE_INT32}, // 3 Minimum operate time
      {"MaxOpTmms.setVal", IEC_TYPE_INT32}, // 4 Maximum operate time
      {"OpDlTmms.setVal" , IEC_TYPE_INT32}, // 5 Operate delay time
      {"TypRsCrv.setVal" , IEC_TYPE_INT32}, // 6 Type of reset curve, assume lineair, value is ignored
      {"RsDlTmms.setVal" , IEC_TYPE_INT32}  // 7 Reset delay time

  };

  // some sane defaults
  inst->StrVal = 100; // 100 Amps
  inst->TmMult = 0.1; // multiplier 0.1
  inst->MinOpTmms = 200; // 200 ms
  inst->MaxOpTmms = 800; // 800 ms 
  inst->OpDlTmms = 100;  // 100 ms operate delay
  inst->RsDlTmms = 500;  // 500 ms reset delay time
  // Retrieve all values
  int retrieved = IecServer_getDataPoints(server, ln, dataPoints, 8);

  // assign them in the ptoc
  if (dataPoints[1].success) {
      inst->StrVal = dataPoints[1].value.floatVal;
  }
  else {
    printf("WARNING: PTOC trip current attribute: StrVal set to 0, please define it using <DOI name='StrVal'><SDI name='setMAg'><DAI name='f'><Val>[value]</Val></DAI></SDI></DOI>\n");
  }
  if (dataPoints[2].success) {
      inst->TmMult = dataPoints[2].value.floatVal;
  }
  if (dataPoints[3].success) {
      inst->MinOpTmms = (float)dataPoints[3].value.int32Val;
  }
  if (dataPoints[4].success) {
      inst->MaxOpTmms = (float)dataPoints[4].value.int32Val;
  }
  if (dataPoints[5].success) {
      inst->OpDlTmms = (float)dataPoints[5].value.int32Val;
  }
  if (dataPoints[7].success) {
      inst->RsDlTmms = (float)dataPoints[7].value.int32Val;
  }


  if (input != NULL)
  {
    InputEntry *extRef = input->extRefs;

    while (extRef != NULL)
    {
      if (strcmp(extRef->intAddr, "PTOC_Amp1") == 0)
      {
        inst->dspI = init_dsp_I(server, extRef);//this is to reference the first extref
        DSP_add_callback_on_update(inst->dspI,PTOC_callback_SMV, inst);//called when DSP has processed data
      }
      if (strcmp(extRef->intAddr, "PTOC_Amp3") == 0) // find extref for the last SMV phase, using the intaddr, so that all values are updated, we ignore nutral in case we have 3 phase, and neutral is calculated
      {
        extRef->callBack = (callBackFunction)get_DSP_processing_callback(inst->dspI);
        extRef->callBackParam = inst->dspI;
      }
      extRef = extRef->sibling;
    }
  }

  return inst;
}
