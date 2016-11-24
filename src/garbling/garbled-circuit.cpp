#include "garbling/garbled-circuit.h"

GarbledCircuit::GarbledCircuit(Circuit& circuit) :
  circuit(circuit),
  garbled_tables(NumTables(circuit), CSEC_BYTES),
  size(garbled_tables.size) {
}

GarbledCircuit::GarbledCircuit(Circuit& circuit, uint8_t tables) :
  circuit(circuit),
  garbled_tables(tables ? BYTEArrayVector(NumTables(circuit), CSEC_BYTES) : BYTEArrayVector()),
  size(tables ? TotalTableSize(circuit): 0) {
}

uint8_t* GarbledCircuit::T_G(uint32_t idx) {
  return T_G(garbled_tables.GetArray(), circuit, idx);
}

uint8_t* GarbledCircuit::T_E(uint32_t idx) {
  return T_E(garbled_tables.GetArray(), circuit, idx);
}

uint8_t* GarbledCircuit::GetTables() {
  return garbled_tables.GetArray();
}