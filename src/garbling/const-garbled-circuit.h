#ifndef DUPLO_GARBLING_CONSTGARBLEDCIRCUIT_H_
#define DUPLO_GARBLING_CONSTGARBLEDCIRCUIT_H_

#include "garbling/garbled-circuit.h"

class ConstGarbledCircuit : public GarbledCircuit {
private:
  std::vector<uint8_t> aux_info; //Cannot be BYTEArrayVector as entires vary in size

public:
  ConstGarbledCircuit(Circuit& circuit);
  ConstGarbledCircuit(Circuit& circuit, uint8_t tables);
  uint8_t* GetAuxArray();
  uint8_t* inp_key_commit0(uint32_t idx = 0);
  uint8_t* out_key_commit0(uint32_t idx = 0);
  uint8_t* delta_commit0();

  uint8_t* inp_key_commit1(uint32_t idx = 0);
  uint8_t* out_key_commit1(uint32_t idx = 0);
  uint8_t* delta_commit1();

  uint8_t* inp_bit_commit0(uint32_t idx = 0);
  uint8_t* out_bit_commit0(uint32_t idx = 0);
  uint8_t* inp_bit_commit1(uint32_t idx = 0);
  uint8_t* out_bit_commit1(uint32_t idx = 0);

  static uint64_t AuxDataSize(Circuit& circuit) {
    return //0 and 1 key shares
    2 * (circuit.num_inp_wires * CODEWORD_BYTES +
    circuit.num_out_wires * CODEWORD_BYTES +
    CODEWORD_BYTES) +
    //0 and 1 shares bit shares
    2 * (circuit.num_inp_wires + circuit.num_out_wires) * BIT_CODEWORD_BYTES;
  };

  static uint8_t* inp_key_commit0(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return aux_info + idx * CODEWORD_BYTES;
  };

  static uint8_t* out_key_commit0(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return inp_key_commit0(circuit, aux_info, circuit.num_inp_wires) + idx * CODEWORD_BYTES;
  };

  static uint8_t* delta_commit0(Circuit& circuit, uint8_t* aux_info) {
    return out_key_commit0(circuit, aux_info, circuit.num_out_wires);
  };

  static uint8_t* inp_key_commit1(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return delta_commit0(circuit, aux_info) + (1 + idx) * CODEWORD_BYTES;
  };

  static uint8_t* out_key_commit1(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return inp_key_commit1(circuit, aux_info, circuit.num_inp_wires) + idx * CODEWORD_BYTES;
  };

  static uint8_t* delta_commit1(Circuit& circuit, uint8_t* aux_info) {
    return out_key_commit1(circuit, aux_info, circuit.num_out_wires);
  };

  static uint8_t* inp_bit_commit0(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return delta_commit1(circuit, aux_info) + CODEWORD_BYTES + idx * BIT_CODEWORD_BYTES;
  };

  static uint8_t* out_bit_commit0(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return inp_bit_commit0(circuit, aux_info, circuit.num_inp_wires) + idx * BIT_CODEWORD_BYTES;
  };

  static uint8_t* inp_bit_commit1(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return out_bit_commit0(circuit, aux_info, circuit.num_out_wires) + idx * BIT_CODEWORD_BYTES;
  };

  static uint8_t* out_bit_commit1(Circuit& circuit, uint8_t* aux_info, uint32_t idx = 0) {
    return inp_bit_commit1(circuit, aux_info, circuit.num_inp_wires) + idx * BIT_CODEWORD_BYTES;
  };
};

#endif /* DUPLO_GARBLING_CONSTGARBLEDCIRCUIT_H_ */