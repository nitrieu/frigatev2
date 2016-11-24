
#include "garbling/eval-garbled-circuit.h"

EvalGarbledCircuit::EvalGarbledCircuit(Circuit& circuit) :
  GarbledCircuit(circuit),
  aux_info(TotalAuxDataSize(circuit)) {
}

EvalGarbledCircuit::EvalGarbledCircuit(Circuit& circuit, uint8_t tables) :
  GarbledCircuit(circuit, tables),
  aux_info(!tables ? std::vector<uint8_t>(TotalAuxDataSize(circuit)) : std::vector<uint8_t>()) {
}

uint8_t* EvalGarbledCircuit::GetAuxArray() {
  return aux_info.data();
}

uint8_t* EvalGarbledCircuit::inp_key_share(uint32_t idx) {
  // return aux_info.data() + idx * CODEWORD_BYTES;
  return inp_key_share(circuit, aux_info.data(), idx);
}

uint8_t* EvalGarbledCircuit::out_key_share(uint32_t idx) {
  // return inp_key_share(circuit.num_inp_wires) + idx * CODEWORD_BYTES;

  return out_key_share(circuit, aux_info.data(), idx);
}

uint8_t* EvalGarbledCircuit::delta_share() {
  // return out_key_share(circuit.num_out_wires);

  return delta_share(circuit, aux_info.data());
}

uint8_t* EvalGarbledCircuit::inp_bit_share(uint32_t idx) {
  // return delta_share() + CODEWORD_BYTES + idx * BIT_CODEWORD_BYTES;

  return inp_bit_share(circuit, aux_info.data(), idx);
}

uint8_t* EvalGarbledCircuit::out_bit_share(uint32_t idx) {
  // return inp_bit_share(circuit.num_inp_wires) + idx * BIT_CODEWORD_BYTES;

  return out_bit_share(circuit, aux_info.data(), idx);
}

uint8_t* EvalGarbledCircuit::inp_soldering(uint32_t idx) {
  // return out_bit_share(circuit.num_out_wires) + idx * CSEC_BYTES;

  return inp_soldering(circuit, aux_info.data(), idx);
}

uint8_t* EvalGarbledCircuit::out_soldering(uint32_t idx) {
  // return inp_soldering(circuit.num_inp_wires) + idx * CSEC_BYTES;

  return out_soldering(circuit, aux_info.data(), idx);
}

uint8_t* EvalGarbledCircuit::delta_soldering() {
  // return out_soldering(circuit.num_out_wires);

  return delta_soldering(circuit, aux_info.data());
}