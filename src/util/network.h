#ifndef DUPLO_UTIL_NETWORK_H_
#define DUPLO_UTIL_NETWORK_H_

#include "OTExtension/util/socket.h"
#include "OTExtension/util/rcvthread.h"
#include "OTExtension/util/sndthread.h"
#include "OTExtension/util/channel.h"

#define RETRY_CONNECT   1000
#define CONNECT_TIMEO_MILISEC 10000

class Network {
public:
  Network(const char m_nAddr[], USHORT m_nPort, uint32_t role);

  void ConnectAndStart();
  void ListenAndStart();
  BOOL Connect();
  BOOL Listen();

  const char* m_nAddr;
  USHORT m_nPort;
  uint32_t role; //m_nPID is just used for the role of the current party. Only used for prints. Consider deleting....
  CSocket* m_vSocket;
  SndThread* sndthread;
  RcvThread* rcvthread;
};

#endif /* DUPLO_UTIL_NETWORK_H_ */