#include "garbling/garbling-handler.h"

GarblingHandler::GarblingHandler() {
  aes128_load_key(global_aes_key, key_schedule);
}

void GarblingHandler::GarbleCircuit(uint8_t input_zero_keys[], uint8_t output_zero_keys[], uint8_t delta[], GarbledCircuit& garbled_circuit, uint8_t garbled_hash[]) {

  Circuit& plain_circuit = garbled_circuit.circuit;
  GarbleCircuit(input_zero_keys, output_zero_keys, delta, garbled_circuit);
  HashGarbledCircuitTables(plain_circuit, garbled_circuit.GetTables(), garbled_hash);
}

void GarblingHandler::GarbleCircuit(uint8_t input_zero_keys[], uint8_t output_zero_keys[], uint8_t delta[], GarbledCircuit& garbled_circuit) {

  Circuit& plain_circuit = garbled_circuit.circuit;
  std::vector<__m128i> intrin_values(plain_circuit.num_wires);

  __m128i intrin_delta = _mm_lddqu_si128((__m128i *) delta);

  //Load input 0-keys into intrin_values
  for (int i = 0; i < plain_circuit.num_inp_wires; ++i) {
    intrin_values[i] = _mm_lddqu_si128((__m128i *) (input_zero_keys + i * CSEC_BYTES));
  }

  //Garble circuit
  uint32_t curr_garbling_idx = 0;
  uint32_t curr_and_gate = 0;
  for (int i = 0; i < plain_circuit.num_gates; ++i) {
    Gate& g = plain_circuit.gates[i];
    if (g.type == NOT) {
      intrin_values[g.out_wire] = _mm_xor_si128(intrin_values[g.left_wire], intrin_delta);
    } else if (g.type == XOR) {
      intrin_values[g.out_wire] = _mm_xor_si128(intrin_values[g.left_wire], intrin_values[g.right_wire]);
    } else if (g.type == NXOR) {
      intrin_values[g.out_wire] = _mm_xor_si128(intrin_values[g.left_wire], intrin_values[g.right_wire]);
      intrin_values[g.out_wire] = _mm_xor_si128(intrin_values[g.out_wire], intrin_delta);
    } else {
      IntrinGarbleGate(garbled_circuit.T_G(curr_and_gate), garbled_circuit.T_E(curr_and_gate), intrin_values[g.left_wire], intrin_values[g.right_wire], intrin_values[g.out_wire], intrin_delta, curr_garbling_idx, key_schedule, g.type);
      ++curr_and_gate;
      curr_garbling_idx += 2;
    }
  }

  //Store output keys to output_zero_keys
  for (int i = 0; i < plain_circuit.num_out_wires; ++i) {
    _mm_storeu_si128((__m128i*) (output_zero_keys + i * CSEC_BYTES), intrin_values[plain_circuit.out_wires_start + i]);
  }
}

void GarblingHandler::GarbleInpBucket(uint8_t hash_val[], uint8_t input_key[], uint32_t id) {
  __m128i input_key_128 = _mm_lddqu_si128((__m128i *) input_key);

  __m128i id_128 = (__m128i) _mm_load_ss((float*) &id);

  __m128i hash_val_128;
  AESHash(input_key_128, hash_val_128, id_128, key_schedule);

  _mm_storeu_si128((__m128i*) hash_val, hash_val_128);
}

void GarblingHandler::EncodeInput(uint8_t input_zero_keys[], uint8_t delta[], uint8_t input[], uint8_t input_keys[], uint32_t num_inputs) {

  for (int i = 0; i < num_inputs; ++i) {
    std::copy(input_zero_keys + i * CSEC_BYTES, input_zero_keys + (i + 1) * CSEC_BYTES, input_keys + i * CSEC_BYTES);
    if (GetBit(i, input)) {
      XOR_128(input_keys + i * CSEC_BYTES, delta);
    }
  }
}

void GarblingHandler::EvalGarbledCircuit(uint8_t input_keys[], Circuit& circuit, uint8_t garbled_tables[], uint8_t output_keys[]) {

  std::vector<__m128i> intrin_values(circuit.num_wires);

  //Load input keys into intrin_values
  for (int i = 0; i < circuit.num_inp_wires; ++i) {
    intrin_values[i] = _mm_lddqu_si128((__m128i *) (input_keys + i * CSEC_BYTES));
  }

  //Eval circuit
  uint32_t curr_and_gate = 0;
  uint32_t curr_garbling_idx = 0;
  for (int i = 0; i < circuit.num_gates; ++i) {
    Gate& g = circuit.gates[i];
    if (g.type == NOT) {
      intrin_values[g.out_wire] = intrin_values[g.left_wire];
    } else if ((g.type == XOR) || (g.type == NXOR)) {
      intrin_values[g.out_wire] = _mm_xor_si128(intrin_values[g.left_wire], intrin_values[g.right_wire]);
    } else {
      IntrinEvalGate(GarbledCircuit::T_G(garbled_tables, circuit, curr_and_gate), GarbledCircuit::T_E(garbled_tables, circuit, curr_and_gate), intrin_values[g.left_wire], intrin_values[g.right_wire], intrin_values[g.out_wire], curr_garbling_idx, key_schedule);

      ++curr_and_gate;
      curr_garbling_idx += 2;
    }
  }

  for (int i = 0; i < circuit.num_out_wires; ++i) {
    __m128i curr_out_key = _mm_lddqu_si128((__m128i *) (output_keys + i * CSEC_BYTES));
    curr_out_key = _mm_xor_si128(curr_out_key, intrin_values[circuit.out_wires_start + i]);
    _mm_storeu_si128((__m128i*) (output_keys + i * CSEC_BYTES), curr_out_key);
  }
}

void GarblingHandler::EvalGarbledCircuitSolderings(uint8_t input_keys[], Circuit& circuit, uint8_t garbled_tables[], uint8_t solderings[], uint8_t output_keys[]) {

  std::vector<__m128i> intrin_values(circuit.num_wires);

  __m128i delta_soldering = _mm_lddqu_si128((__m128i *) EvalGarbledCircuit::delta_soldering_no_aux(circuit, solderings));
  //Load input keys into intrin_values
  __m128i current_soldering;
  for (int i = 0; i < circuit.num_inp_wires; ++i) {
    intrin_values[i] = _mm_lddqu_si128((__m128i *) (input_keys + i * CSEC_BYTES));

    if (GetLSB(intrin_values[i])) {
      intrin_values[i] = _mm_xor_si128(intrin_values[i], delta_soldering);
    }

    current_soldering = _mm_lddqu_si128((__m128i *) EvalGarbledCircuit::inp_soldering_no_aux(circuit, solderings, i));
    intrin_values[i] = _mm_xor_si128(intrin_values[i], current_soldering);
  }

  //Eval circuit
  uint32_t curr_and_gate = 0;
  uint32_t curr_garbling_idx = 0;
  for (int i = 0; i < circuit.num_gates; ++i) {
    Gate& g = circuit.gates[i];
    if (g.type == NOT) {
      intrin_values[g.out_wire] = intrin_values[g.left_wire];
    } else if ((g.type == XOR) || (g.type == NXOR)) {
      intrin_values[g.out_wire] = _mm_xor_si128(intrin_values[g.left_wire], intrin_values[g.right_wire]);
    } else {
      IntrinEvalGate(GarbledCircuit::T_G(garbled_tables, circuit, curr_and_gate), GarbledCircuit::T_E(garbled_tables, circuit, curr_and_gate), intrin_values[g.left_wire], intrin_values[g.right_wire], intrin_values[g.out_wire], curr_garbling_idx, key_schedule);

      ++curr_and_gate;
      curr_garbling_idx += 2;
    }
  }

  for (int i = 0; i < circuit.num_out_wires; ++i) {
    current_soldering = _mm_lddqu_si128((__m128i *) EvalGarbledCircuit::out_soldering_no_aux(circuit, solderings, i));
    intrin_values[circuit.out_wires_start + i] = _mm_xor_si128(intrin_values[circuit.out_wires_start + i], current_soldering);

    if (GetLSB((intrin_values[circuit.out_wires_start + i]))) {
      intrin_values[circuit.out_wires_start + i] = _mm_xor_si128(intrin_values[circuit.out_wires_start + i], delta_soldering);
    }

    _mm_storeu_si128((__m128i*) (output_keys + i * CSEC_BYTES), intrin_values[circuit.out_wires_start + i]);
  }
}
