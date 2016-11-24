#ifndef DUPLO_DOT_EXT_SND_H_
#define DUPLO_DOT_EXT_SND_H_

#include "dot/alsz-dot-ext.h"

class ALSZDOTExtSnd : public ALSZDOTExt {
public:
  ALSZDOTExtSnd(CommonTools& common_tools, bool set_lsb_delta);

  void InitOTSender();

  void Send(int num_OT, uint8_t base[], uint8_t delta[]);
  void PrivacyAmplification(int num_OT, uint8_t base_inner[], uint8_t delta_inner[], uint8_t base[], uint8_t delta[]);

  ALSZOTExtSnd sender;

  bool set_lsb_delta;
};

#endif /* DUPLO_DOT_EXT_SND_H_ */