#ifndef DUPLO_DOT_EXT_REC_H_
#define DUPLO_DOT_EXT_REC_H_

#include "dot/alsz-dot-ext.h"

class ALSZDOTExtRec : public ALSZDOTExt {
public:
  ALSZDOTExtRec(CommonTools& common_tools);
  void InitOTReceiver();

  void Receive(int num_OT, uint8_t response[], uint8_t choices[]);
  void PrivacyAmplification(int num_OT, uint8_t response_inner[], uint8_t response[]);

  ALSZOTExtRec receiver;

};

#endif /* DUPLO_DOT_EXT_REC_H_ */