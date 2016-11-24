#ifndef DUPLO_UTIL_CHANNEL_H_
#define DUPLO_UTIL_CHANNEL_H_

#include "util/util.h"

#include "zeromq/include/zmq.hpp"

class Channel {
public:
  Channel(std::string ip_address, uint16_t port_push, uint16_t port_pull, uint8_t net_role, zmq::context_t& context);

  std::vector<uint64_t> bytes_received_vec;
  std::vector<uint64_t> bytes_sent_vec;

  uint64_t received_pointer;
  uint64_t sent_pointer;

  void Receive(uint8_t buf[], uint64_t num_bytes);
  void ReceiveBlocking(uint8_t buf[], uint64_t num_bytes, bool no_blocking = 0);
  void Send(uint8_t buf[], uint64_t num_bytes);
  void SendBlocking(uint8_t buf[], uint64_t num_bytes, bool no_blocking = 0);

  void ResetSentBytes();
  void ResetReceivedBytes();
  uint64_t GetCurrentBytesReceived();
  uint64_t GetTotalBytesReceived();
  uint64_t GetCurrentBytesSent();
  uint64_t GetTotalBytesSent();

  zmq::socket_t receive_socket;
  zmq::socket_t send_socket;


  uint8_t net_role;
  std::string receive_s;
  std::string send_s;
  
  const uint64_t max_num_send_bytes = std::numeric_limits<int>::max();
};

#endif /* DUPLO_UTIL_CHANNEL_H_ */