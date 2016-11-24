#include "util/channel.h"

Channel::Channel(std::string ip_address, uint16_t port_push, uint16_t port_pull, uint8_t net_role, zmq::context_t& context) : receive_socket(context, ZMQ_PULL), send_socket(context, ZMQ_PUSH), bytes_received_vec(1), received_pointer(0), bytes_sent_vec(1), sent_pointer(0), net_role(net_role) {

  zmq_setsockopt(&send_socket, ZMQ_LINGER, 0, sizeof(int));
  zmq_setsockopt(&receive_socket, ZMQ_LINGER, 0, sizeof(int));
  if (net_role) { //client
    receive_s = "tcp://" + ip_address + ":" + std::to_string(port_pull);
    receive_socket.connect(receive_s);

    send_s = "tcp://" + ip_address + ":" + std::to_string(port_push);
    send_socket.connect(send_s);
  } else { //server
    receive_s = "tcp://*:" + std::to_string(port_push);
    receive_socket.bind(receive_s);

    send_s = "tcp://*:" + std::to_string(port_pull);
    send_socket.bind(send_s);
  }
}

void Channel::Receive(uint8_t buf[], uint64_t num_bytes) {
  ReceiveBlocking(buf, num_bytes, ZMQ_DONTWAIT);
}

void Channel::ReceiveBlocking(uint8_t buf[], uint64_t num_bytes, bool no_blocking) {

  uint64_t q = num_bytes / max_num_send_bytes;
  uint64_t r = num_bytes % max_num_send_bytes;

  for (int i = 0; i < q; ++i) {
    receive_socket.recv((void*) (buf + i * max_num_send_bytes), max_num_send_bytes, no_blocking);
    bytes_received_vec[received_pointer] += max_num_send_bytes;
  }

  receive_socket.recv((void*) (buf + q * max_num_send_bytes), r, no_blocking);
  bytes_received_vec[received_pointer] += r;

}

void Channel::Send(uint8_t buf[], uint64_t num_bytes) {
  SendBlocking(buf, num_bytes, ZMQ_DONTWAIT);

}

void Channel::SendBlocking(uint8_t buf[], uint64_t num_bytes, bool no_blocking) {
  uint64_t q = num_bytes / max_num_send_bytes;
  uint64_t r = num_bytes % max_num_send_bytes;

  for (int i = 0; i < q; ++i) {
    send_socket.send((void*) (buf + i * max_num_send_bytes), max_num_send_bytes, no_blocking);
    bytes_sent_vec[sent_pointer] += max_num_send_bytes;
  }

  send_socket.send((void*) (buf + q * max_num_send_bytes), r, no_blocking);
  bytes_sent_vec[sent_pointer] += r;
}

void Channel::ResetReceivedBytes() {
  bytes_received_vec.emplace_back(0);
  ++received_pointer;
}

void Channel::ResetSentBytes() {
  bytes_sent_vec.emplace_back(0);
  ++sent_pointer;
}

uint64_t Channel::GetCurrentBytesReceived() {
  return bytes_received_vec[received_pointer];
}

uint64_t Channel::GetTotalBytesReceived() {
  uint64_t res = 0;
  for (uint64_t t : bytes_received_vec) {
    res += t;
  }
  return res;
}

uint64_t Channel::GetCurrentBytesSent() {
  return bytes_sent_vec[sent_pointer];
}

uint64_t Channel::GetTotalBytesSent() {
  uint64_t res = 0;
  for (uint64_t t : bytes_sent_vec) {
    res += t;
  }
  return res;
}