
#include "byte-array-vec.h"

BYTEArrayVector::BYTEArrayVector(uint64_t num_entries, uint64_t entry_size) : 
  vec(num_entries * entry_size),
  entry_size(entry_size),
  num_entries(num_entries),
  size(num_entries * entry_size) {
}

BYTEArrayVector::BYTEArrayVector() {

}

uint8_t* BYTEArrayVector::operator[](const uint64_t idx) {
    return vec.data() + idx * entry_size;
}

uint8_t* BYTEArrayVector::GetArray() {
    return vec.data();
}

void BYTEArrayVector::FreeMem() {
  vec.clear();
  vec.shrink_to_fit();
}