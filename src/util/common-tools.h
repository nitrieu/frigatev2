#ifndef UTIL_DUPLO_PARAMS_H_
#define UTIL_DUPLO_PARAMS_H_

#include "OTExtension/util/crypto/crypto.h"
#include "prg/random.h"
#include "util/network.h"
#include "util/channel.h"

class CommonTools {
public:
  CommonTools(uint8_t* seed, std::string ip_address, uint16_t port, uint8_t net_role, zmq::context_t& context, uint32_t exec_id = GLOBAL_PARAMS_CHAN);
  CommonTools(CommonTools& MainCommonTools, uint8_t* seed, uint32_t exec_id);

  uint8_t global_aes_key[AES_KEY_BYTES] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  crypto crypt;
  PRNG rnd;

  int exec_id;
  
  //Network related
  zmq::context_t& context;
  std::string ip_address;
  uint16_t port;
  uint8_t net_role;
  Channel chan;
};

#endif /* UTIL_DUPLO_PARAMS_H_ */