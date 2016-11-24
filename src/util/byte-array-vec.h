#ifndef DUPLO_UTIL_BYTEARRAYVEC_H_
#define DUPLO_UTIL_BYTEARRAYVEC_H_

#include "util/typedefs.h"

class BYTEArrayVector {
private:
  std::vector<uint8_t> vec;
  
public:

  BYTEArrayVector(uint64_t num_entries, uint64_t entry_size);
  BYTEArrayVector();
  uint8_t* operator[] (const uint64_t idx);
  uint8_t* GetArray();

  void FreeMem();

  uint64_t size;
  uint64_t num_entries;
  uint64_t entry_size;
};

#endif /* DUPLO_UTIL_BYTEARRAYVEC_H_ */