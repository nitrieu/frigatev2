#include "util/common-tools.h"

CommonTools::CommonTools(uint8_t* seed, std::string ip_address, uint16_t port, uint8_t net_role, zmq::context_t& context, uint32_t exec_id) : crypt(CSEC, seed), context(context), exec_id(exec_id), ip_address(ip_address), port(port), net_role(net_role), chan(ip_address, port + exec_id + 1, port + exec_id + 1 + MAX_TOTAL_PARAMS, net_role, context) {

  rnd.SetSeed(seed);
}

CommonTools::CommonTools(CommonTools& MainCommonTools, uint8_t* seed, uint32_t exec_id) : CommonTools(seed, MainCommonTools.ip_address, MainCommonTools.port, MainCommonTools.net_role, MainCommonTools.context, exec_id) {
  
}