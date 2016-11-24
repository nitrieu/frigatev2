#ifndef DUPLO_GARBLING_GARBLINGHANDLER_H_
#define DUPLO_GARBLING_GARBLINGHANDLER_H_

#include "garbling/garbled-circuit.h"
#include "garbling/eval-garbled-circuit.h"

#include "circuit/circuit.h"
#include "util/common-tools.h"

class GarblingHandler {
public:
  GarblingHandler();
  void GarbleCircuit(uint8_t input_zero_keys[], uint8_t output_zero_keys[], uint8_t delta[], GarbledCircuit& garbled_circuit, uint8_t garbled_hash[]);

  void GarbleCircuit(uint8_t input_zero_keys[], uint8_t output_zero_keys[], uint8_t delta[], GarbledCircuit& garbled_circuit);

  void GarbleInpBucket(uint8_t hash_val[], uint8_t input_key[], uint32_t id);

  void EncodeInput(uint8_t input_zero_keys[], uint8_t delta[], uint8_t input[], uint8_t input_keys[], uint32_t num_inputs);

  void EvalGarbledCircuit(uint8_t input_keys[], Circuit& circuit, uint8_t garbled_tables[], uint8_t output_keys[]);
  void EvalGarbledCircuitSolderings(uint8_t input_keys[], Circuit& circuit, uint8_t garbled_tables[], uint8_t solderings[], uint8_t output_keys[]);

  __m128i key_schedule[11];
};

static void HashGarbledCircuitTables(Circuit& circuit, uint8_t garbled_tables[], uint8_t garbled_hash[]) {

  std::fill(garbled_hash, garbled_hash + CSEC_BYTES, 0);
  for (int i = 0; i < 2 * circuit.num_non_free_gates; ++i) {
    XOR_128(garbled_hash, garbled_tables + i * CSEC_BYTES);
  }
};

static __m128i invert_array[] = {_mm_setzero_si128(), _mm_set1_epi32(0xFFFFFFFF)};

//The below gate_constants_array is coupled with the GATE enum, if the order of gates is changed there it needs to be changed here as well
static uint8_t gate_constants_array[4][3] = {
  {0, 0, 0}, //AND
  {0, 0, 1}, //NAND
  {1, 1, 1}, //OR
  {1, 1, 0} //NOR
};

static void DecodeGarbledOutput(uint8_t output_keys[], uint8_t output_decodings[], uint8_t output_result[], uint32_t num_outputs) {

  //Use output_decodings to optain the output and write this to output_result
  for (int i = 0; i < num_outputs; ++i) {
    SetBit(i, GetBit(i, output_decodings) ^ GetLSB(output_keys + i * CSEC_BYTES), output_result);
  }
};

//Static context for added performance
#define DO_ENC_BLOCK(m,k) \
    do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

#define DO_ENC_BLOCK_2(m0, m1, k) \
    do{\
        m0 = _mm_xor_si128       (m0, k[ 0]); \
        m1 = _mm_xor_si128       (m1, k[ 0]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 1]); \
        m1 = _mm_aesenc_si128    (m1, k[ 1]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 2]); \
        m1 = _mm_aesenc_si128    (m1, k[ 2]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 3]); \
        m1 = _mm_aesenc_si128    (m1, k[ 3]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 4]); \
        m1 = _mm_aesenc_si128    (m1, k[ 4]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 5]); \
        m1 = _mm_aesenc_si128    (m1, k[ 5]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 6]); \
        m1 = _mm_aesenc_si128    (m1, k[ 6]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 7]); \
        m1 = _mm_aesenc_si128    (m1, k[ 7]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 8]); \
        m1 = _mm_aesenc_si128    (m1, k[ 8]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 9]); \
        m1 = _mm_aesenc_si128    (m1, k[ 9]); \
\
        m0 = _mm_aesenclast_si128(m0, k[10]);\
        m1 = _mm_aesenclast_si128(m1, k[10]);\
    }while(0)

#define DO_ENC_BLOCK_4(m0, m1, m2, m3, k) \
    do{\
        m0 = _mm_xor_si128       (m0, k[ 0]); \
        m1 = _mm_xor_si128       (m1, k[ 0]); \
        m2 = _mm_xor_si128       (m2, k[ 0]); \
        m3 = _mm_xor_si128       (m3, k[ 0]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 1]); \
        m1 = _mm_aesenc_si128    (m1, k[ 1]); \
        m2 = _mm_aesenc_si128    (m2, k[ 1]); \
        m3 = _mm_aesenc_si128    (m3, k[ 1]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 2]); \
        m1 = _mm_aesenc_si128    (m1, k[ 2]); \
        m2 = _mm_aesenc_si128    (m2, k[ 2]); \
        m3 = _mm_aesenc_si128    (m3, k[ 2]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 3]); \
        m1 = _mm_aesenc_si128    (m1, k[ 3]); \
        m2 = _mm_aesenc_si128    (m2, k[ 3]); \
        m3 = _mm_aesenc_si128    (m3, k[ 3]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 4]); \
        m1 = _mm_aesenc_si128    (m1, k[ 4]); \
        m2 = _mm_aesenc_si128    (m2, k[ 4]); \
        m3 = _mm_aesenc_si128    (m3, k[ 4]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 5]); \
        m1 = _mm_aesenc_si128    (m1, k[ 5]); \
        m2 = _mm_aesenc_si128    (m2, k[ 5]); \
        m3 = _mm_aesenc_si128    (m3, k[ 5]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 6]); \
        m1 = _mm_aesenc_si128    (m1, k[ 6]); \
        m2 = _mm_aesenc_si128    (m2, k[ 6]); \
        m3 = _mm_aesenc_si128    (m3, k[ 6]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 7]); \
        m1 = _mm_aesenc_si128    (m1, k[ 7]); \
        m2 = _mm_aesenc_si128    (m2, k[ 7]); \
        m3 = _mm_aesenc_si128    (m3, k[ 7]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 8]); \
        m1 = _mm_aesenc_si128    (m1, k[ 8]); \
        m2 = _mm_aesenc_si128    (m2, k[ 8]); \
        m3 = _mm_aesenc_si128    (m3, k[ 8]); \
\
        m0 = _mm_aesenc_si128    (m0, k[ 9]); \
        m1 = _mm_aesenc_si128    (m1, k[ 9]); \
        m2 = _mm_aesenc_si128    (m2, k[ 9]); \
        m3 = _mm_aesenc_si128    (m3, k[ 9]); \
\
        m0 = _mm_aesenclast_si128(m0, k[10]);\
        m1 = _mm_aesenclast_si128(m1, k[10]);\
        m2 = _mm_aesenclast_si128(m2, k[10]);\
        m3 = _mm_aesenclast_si128(m3, k[10]);\
    }while(0)

static inline __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
  keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static inline void aes128_load_key(uint8_t *enc_key, __m128i key_schedule[]) {
  key_schedule[0]  = _mm_lddqu_si128((const __m128i*) enc_key);
  key_schedule[1]  = AES_128_key_exp(key_schedule[0], 0x01);
  key_schedule[2]  = AES_128_key_exp(key_schedule[1], 0x02);
  key_schedule[3]  = AES_128_key_exp(key_schedule[2], 0x04);
  key_schedule[4]  = AES_128_key_exp(key_schedule[3], 0x08);
  key_schedule[5]  = AES_128_key_exp(key_schedule[4], 0x10);
  key_schedule[6]  = AES_128_key_exp(key_schedule[5], 0x20);
  key_schedule[7]  = AES_128_key_exp(key_schedule[6], 0x40);
  key_schedule[8]  = AES_128_key_exp(key_schedule[7], 0x80);
  key_schedule[9]  = AES_128_key_exp(key_schedule[8], 0x1B);
  key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
};

static inline __m128i AESHash(__m128i& value_128, __m128i& id_128, __m128i key_schedule[]) {
  __m128i res = DOUBLE(value_128);
  res = _mm_xor_si128(res, id_128);
  __m128i tmp_input = res;

  DO_ENC_BLOCK(res, key_schedule);

  return _mm_xor_si128(res, tmp_input);
}

static inline void AESHash(__m128i& value_128, __m128i& res, __m128i& id_128, __m128i key_schedule[]) {
  
  res = DOUBLE(value_128);
  res = _mm_xor_si128(res, id_128);
  __m128i tmp_input = res;

  DO_ENC_BLOCK(res, key_schedule);

  res = _mm_xor_si128(res, tmp_input);
}

static inline void DM_HASH(uint8_t res[], uint32_t res_length, uint8_t val[], uint32_t num_bytes) {
  __m128i block;
  __m128i id;

  uint8_t hash_array[AES_KEY_BYTES] = { 0x2c, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xab, 0xcb, 0xf2, 0x15, 0x88, 0x09, 0xcd, 0x43, 0x3c};
  __m128i hash_key_schedule[11];

  uint32_t num_iters = num_bytes / AES_BYTES;

  for (uint32_t i = 0; i < num_iters; ++i) {

    aes128_load_key(hash_array, hash_key_schedule);

    block = _mm_lddqu_si128((__m128i *) (val + i * AES_BYTES));
    id = (__m128i) _mm_load_ss((float*) &i);
    block = AESHash(block, id, hash_key_schedule);
    _mm_storeu_si128((__m128i*) hash_array, block);
  }
  std::copy(hash_array, hash_array + AES_BYTES, res);
  std::fill(res + AES_BYTES, res + HASH_BYTES, 0);
}

static inline void AESHash_2(__m128i& value0, __m128i& value1, __m128i& value0_res, __m128i& value1_res, __m128i& id0, __m128i& id1, __m128i key_schedule[]) {

  value0_res = DOUBLE(value0);
  value1_res = DOUBLE(value1);

  value0_res = _mm_xor_si128(value0_res, id0);
  value1_res = _mm_xor_si128(value1_res, id1);

  __m128i tmp0 = value0_res;
  __m128i tmp1 = value1_res;

  DO_ENC_BLOCK_2(value0_res, value1_res, key_schedule);

  value0_res = _mm_xor_si128(value0_res, tmp0);
  value1_res = _mm_xor_si128(value1_res, tmp1);
}

static inline void AESHash_4(__m128i& value0, __m128i& value1, __m128i& value2, __m128i& value3, __m128i& value0_res, __m128i& value1_res, __m128i& value2_res, __m128i& value3_res, __m128i& id0, __m128i& id1, __m128i key_schedule[]) {

  value0_res = DOUBLE(value0);
  value1_res = DOUBLE(value1);
  value2_res = DOUBLE(value2);
  value3_res = DOUBLE(value3);

  value0_res = _mm_xor_si128(value0_res, id0);
  value1_res = _mm_xor_si128(value1_res, id0);

  value2_res = _mm_xor_si128(value2_res, id1);
  value3_res = _mm_xor_si128(value3_res, id1);

  __m128i tmp0 = value0_res;
  __m128i tmp1 = value1_res;
  __m128i tmp2 = value2_res;
  __m128i tmp3 = value3_res;

  DO_ENC_BLOCK_4(value0_res, value1_res, value2_res, value3_res, key_schedule);

  value0_res = _mm_xor_si128(value0_res, tmp0);
  value1_res = _mm_xor_si128(value1_res, tmp1);
  value2_res = _mm_xor_si128(value2_res, tmp2);
  value3_res = _mm_xor_si128(value3_res, tmp3);
}

//HalfGate Garbling
static inline void IntrinGarbleGate(uint8_t gate_T_G[], uint8_t gate_T_E[], __m128i left_key, __m128i right_key, __m128i& out_key, __m128i& delta, uint32_t id, __m128i key_schedule[], GATE GATE_TYPE) {

  __m128i left_key_delta, right_key_delta, T_G, T_E, id0, id1, tmp, hash_left_key, hash_left_key_delta, hash_right_key, hash_right_key_delta;

  uint8_t left_bit = GetLSB(left_key);
  uint8_t right_bit = GetLSB(right_key);

  left_key_delta = _mm_xor_si128(left_key, delta);
  right_key_delta = _mm_xor_si128(right_key, delta);

  id0 = (__m128i) _mm_load_ss((float*) &id);
  ++id;
  id1 = (__m128i) _mm_load_ss((float*) &id);
  AESHash_4(left_key, left_key_delta, right_key, right_key_delta, hash_left_key, hash_left_key_delta, hash_right_key, hash_right_key_delta, id0, id1, key_schedule);

  T_G = _mm_xor_si128(hash_left_key, hash_left_key_delta);
  T_G = _mm_xor_si128(T_G, _mm_and_si128(delta, invert_array[gate_constants_array[GATE_TYPE][1] ^ right_bit]));

  // if (left_bit) {
  //   out_key = hash_left_key_delta;
  // } else {
  //   out_key = hash_left_key;
  // }
  out_key = _mm_setzero_si128(); //out_key is initially zero
  out_key = _mm_xor_si128(out_key, _mm_and_si128(hash_left_key_delta, invert_array[left_bit]));
  out_key = _mm_xor_si128(out_key, _mm_and_si128(hash_left_key, invert_array[!left_bit]));

  out_key = _mm_xor_si128(out_key, _mm_and_si128(delta, invert_array[((left_bit ^ gate_constants_array[GATE_TYPE][0]) & (right_bit ^ gate_constants_array[GATE_TYPE][1])) ^ gate_constants_array[GATE_TYPE][2]]));

  T_E = _mm_xor_si128(hash_right_key, hash_right_key_delta);
  T_E = _mm_xor_si128(T_E, left_key);
  T_E = _mm_xor_si128(T_E, _mm_and_si128(delta, invert_array[gate_constants_array[GATE_TYPE][0]]));
  
  // if (right_bit) {
  //   out_key = _mm_xor_si128(out_key, hash_right_key_delta);
  // } else {
  //   out_key = _mm_xor_si128(out_key, hash_right_key);
  // }
  out_key = _mm_xor_si128(out_key, _mm_and_si128(hash_right_key_delta, invert_array[right_bit]));
  out_key = _mm_xor_si128(out_key, _mm_and_si128(hash_right_key, invert_array[!right_bit]));


  _mm_storeu_si128((__m128i*) gate_T_G, T_G);
  _mm_storeu_si128((__m128i*) gate_T_E, T_E);
};

//HalfGate Evaluation
static inline __m128i IntrinEvalGate(uint8_t gate_T_G[], uint8_t gate_T_E[], __m128i left_key_128, __m128i right_key_128, __m128i& out_key_128, uint32_t id, __m128i key_schedule[]) {

  __m128i T_G_128 = _mm_lddqu_si128((__m128i *) gate_T_G);
  __m128i T_E_128 = _mm_lddqu_si128((__m128i *) gate_T_E);

  //Old method
  // __m128i id_128 = (__m128i) _mm_load_ss((float*) &id);
  // //////First Hash//////
  // __m128i res = _mm_xor_si128(DOUBLE(left_key_128), id_128);
  // out_key_128 = res;
  // DO_ENC_BLOCK(res, key_schedule);
  // out_key_128 = _mm_xor_si128(out_key_128, res);
  // //////First Hash//////

  // ++id;
  // id_128 = (__m128i) _mm_load_ss((float*) &id);
  // //////Second Hash//////
  // res = _mm_xor_si128(DOUBLE(right_key_128), id_128);
  // out_key_128 = _mm_xor_si128(out_key_128, res);
  // DO_ENC_BLOCK(res, key_schedule);
  // out_key_128 = _mm_xor_si128(out_key_128, res);
  // //////Second Hash//////

  __m128i id0 = (__m128i) _mm_load_ss((float*) &id);
  ++id;
  __m128i id1 = (__m128i) _mm_load_ss((float*) &id);
  __m128i tmp;
  AESHash_2(left_key_128, right_key_128, out_key_128, tmp, id0, id1, key_schedule);
  out_key_128 = _mm_xor_si128(out_key_128, tmp);

  out_key_128 = _mm_xor_si128(out_key_128, _mm_and_si128(T_G_128, invert_array[GetLSB(left_key_128)]));

  out_key_128 = _mm_xor_si128(out_key_128, _mm_and_si128(T_E_128, invert_array[GetLSB(right_key_128)]));
  out_key_128 = _mm_xor_si128(out_key_128, _mm_and_si128(left_key_128, invert_array[GetLSB(right_key_128)]));
};

//Wire Authenticators production
static inline void Auth(uint8_t key[], uint8_t delta[], uint32_t id, uint8_t h_0[], uint8_t h_1[], __m128i key_schedule[]) {

  __m128i delta_128 = _mm_lddqu_si128((__m128i *) delta);
  __m128i key_128 = _mm_lddqu_si128((__m128i *) key);

  __m128i id_128 = (__m128i) _mm_load_ss((float*) &id);

  __m128i key_delta_128 = _mm_xor_si128(key_128, delta_128);

  AESHash_2(key_128, key_delta_128, key_128, key_delta_128, id_128, id_128, key_schedule);

  _mm_storeu_si128((__m128i *) h_0, key_128);
  _mm_storeu_si128((__m128i *) h_1, key_delta_128);
  int res = memcmp(h_0, h_1, AES_BYTES);
  if (res > 0) {
    //Do nothing
  } else if (res < 0) {
    //Swap the order of the authenticators
    uint8_t tmp[AES_BYTES];
    std::copy(h_0, h_0 + AES_BYTES, tmp);
    std::copy(h_1, h_1 + AES_BYTES, h_0);
    std::copy(tmp, tmp + AES_BYTES, h_1);
  } else {
    std::cout << "Congrats, this only happens with prob. 2^-128! It must be your lucky day!" << std::endl;
  }
}

//Verify Wire Authenticators
static inline bool VerifyAuth(uint8_t key[], uint8_t h_0[], uint8_t h_1[], uint32_t id, __m128i key_schedule[]) {

  __m128i key_128 = _mm_lddqu_si128((__m128i *) key);
  __m128i hash_128 = _mm_lddqu_si128((__m128i *) h_0);
  __m128i id_128 = (__m128i) _mm_load_ss((float*) &id);

  key_128 = AESHash(key_128, id_128, key_schedule);

  if (compare128(key_128, hash_128)) {
    return true;
  } else {
    hash_128 = _mm_lddqu_si128((__m128i *) h_1);
    if (compare128(key_128, hash_128)) {
      return true;
    }
  }

  return false; //Didn't match any
}

#endif /* DUPLO_GARBLING_GARBLINGHANDLER_H_ */