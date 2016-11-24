#ifndef DUPLO_UTIL_UTIL_H_
#define DUPLO_UTIL_UTIL_H_

#include "util/typedefs.h"
#include "util/global-constants.h"

#include "prg/random.h"

#include "OTExtension/util/cbitvector.h"

#define PAD_TO_POWER_OF_TWO(e) ( ((uint64_t) 1) << (CeilLog2(e)) )
#define CEIL_DIVIDE(x, y)     (( ((x) + (y)-1)/(y)))
#define BITS_TO_BYTES(bits) (CEIL_DIVIDE((bits), CHAR_BIT))
#define BYTES_TO_BITS(bytes) (bytes * CHAR_BIT)
#define PAD_TO_MULTIPLE(x, y)     ( CEIL_DIVIDE(x, y) * (y))
#define DOUBLE(x) _mm_slli_epi64(x,1)

#define GET_TIME() std::chrono::high_resolution_clock::now()
#define PRINT_TIME(end,begin,str) std::cout << str << ": " << (double) std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() / 1000000 << std::endl;
#define PRINT_TIME_NANO(end,begin,str) std::cout << str << ": " << std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() << std::endl;

#define ThisThreadSleep(sec) std::this_thread::sleep_for(std::chrono::seconds(sec));

static inline void PrintTimePerBucket(std::chrono::time_point<std::chrono::high_resolution_clock> begin, std::chrono::time_point<std::chrono::high_resolution_clock> end, uint32_t num_buckets, std::string msg) {
  uint64_t time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
  std::cout << msg << ": " << (double) time_nano / num_buckets / pow(10, 6) << std::endl;
}

static uint8_t bit_to_byte[] = {0x00, 0xFF};

static inline void XOR_UINT8_T(uint8_t dest[], uint8_t src[], int size) {
  for (int i = 0; i < size; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_UINT8_T(uint8_t dest[], uint8_t src0[], uint8_t src1[], int size) {
  for (int i = 0; i < size; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

static inline void XOR_128(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < AES_BYTES; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_128(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < AES_BYTES; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

//23 bytes
static inline void XOR_CheckBits(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < (CODEWORD_BYTES - CSEC_BYTES); i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_CheckBits(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < (CODEWORD_BYTES - CSEC_BYTES); i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

//39 bytes
static inline void XOR_CodeWords(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < CODEWORD_BYTES; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_BitCodeWords(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < BIT_CODEWORD_BYTES; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_CodeWords(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < CODEWORD_BYTES; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

static inline void XOR_BitCodeWords(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < BIT_CODEWORD_BYTES; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

static inline uint8_t GetBitReversed(int idx, uint8_t array[]) {
  return !!(array[idx >> 3] & MASK_BIT[idx & 0x7]);
};

//MSB has highest index
static inline uint8_t GetBit(int idx, uint8_t array[]) {
  return !!(array[idx >> 3] & BIT[idx & 0x7]);
};

static inline void XORBitReversed(int idx, BYTE b, uint8_t array[]) {
  array[idx >> 3] ^= MASK_SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void XORBit(int idx, BYTE b, uint8_t array[]) {
  array[idx >> 3] ^= SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void SetBitReversed(int idx, uint8_t b, uint8_t array[]) {
  array[idx >> 3] = (array[idx >> 3] & CMASK_BIT[idx & 0x7]) | MASK_SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void SetBit(int idx, uint8_t b, uint8_t array[]) {
  array[idx >> 3] = (array[idx >> 3] & C_BIT[idx & 0x7]) | SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void XORBit(int idx, BYTE a, BYTE b, uint8_t array[]) {
  SetBit(idx, a, array);
  XORBit(idx, b, array);
};

static inline uint8_t GetLSB(__m128i s) {
  int r = _mm_movemask_pd((__m128d) s);
  return (r == 2 || r == 3); //Checks if lsb-1 is set or not. This is only set if lsb(array) is set.
};

//Wrapper
static inline uint8_t GetLSB(uint8_t array[]) {
  __m128i s = _mm_lddqu_si128((__m128i *) (array));
  return GetLSB(s);
};

static inline uint128_t uint8_tTOuint128_t(uint8_t array[]) {
  uint128_t value =
    static_cast<uint128_t>(array[0]) |
    static_cast<uint128_t>(array[1]) << 8 |
    static_cast<uint128_t>(array[2]) << 16 |
    static_cast<uint128_t>(array[3]) << 24 |
    static_cast<uint128_t>(array[4]) << 32 |
    static_cast<uint128_t>(array[5]) << 40 |
    static_cast<uint128_t>(array[6]) << 48 |
    static_cast<uint128_t>(array[7]) << 56 |
    static_cast<uint128_t>(array[8]) << 64 |
    static_cast<uint128_t>(array[9]) << 72 |
    static_cast<uint128_t>(array[10]) << 80 |
    static_cast<uint128_t>(array[11]) << 88 |
    static_cast<uint128_t>(array[12]) << 96 |
    static_cast<uint128_t>(array[13]) << 104 |
    static_cast<uint128_t>(array[14]) << 112 |
    static_cast<uint128_t>(array[15]) << 120;

  return value;
};

static inline bool compare128(__m128i a, __m128i b) {
  __m128i c = _mm_xor_si128(a, b);
  return _mm_testz_si128(c, c);
};

//Multiplies, but does not reduce
//See https://software.intel.com/sites/default/files/m/4/1/2/2/c/1230-Carry-Less-Multiplication-and-The-GCM-Mode_WP_.pdf for source
static inline void mul128_karatsuba(__m128i a, __m128i b, __m128i *res1, __m128i *res2) {
  __m128i tmp3, tmp4, tmp5, tmp6;
  tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
  tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
  tmp4 = _mm_shuffle_epi32(a, 78);
  tmp5 = _mm_shuffle_epi32(b, 78);
  tmp4 = _mm_xor_si128(tmp4, a);
  tmp5 = _mm_xor_si128(tmp5, b);

  tmp4 = _mm_clmulepi64_si128(tmp4, tmp5, 0x00);
  tmp4 = _mm_xor_si128(tmp4, tmp3);
  tmp4 = _mm_xor_si128(tmp4, tmp6);
  tmp5 = _mm_slli_si128(tmp4, 8);
  tmp4 = _mm_srli_si128(tmp4, 8);
  *res1 = _mm_xor_si128(tmp3, tmp5);
  *res2 = _mm_xor_si128(tmp6, tmp4);
};

//The reduction, taking the two results of mul128_karatsuba as input
static inline void gfred128_no_refl(__m128i tmp3, __m128i tmp6, __m128i *res) {
  __m128i tmp7, tmp8, tmp9, tmp10, tmp11, tmp12;
  __m128i XMMMASK = _mm_setr_epi32(0xffffffff, 0x0, 0x0, 0x0);
  tmp7 = _mm_srli_epi32(tmp6, 31);
  tmp8 = _mm_srli_epi32(tmp6, 30);
  tmp9 = _mm_srli_epi32(tmp6, 25);
  tmp7 = _mm_xor_si128(tmp7, tmp8);
  tmp7 = _mm_xor_si128(tmp7, tmp9);

  tmp8 = _mm_shuffle_epi32(tmp7, 147);
  tmp7 = _mm_and_si128(XMMMASK, tmp8);
  tmp8 = _mm_andnot_si128(XMMMASK, tmp8);
  tmp3 = _mm_xor_si128(tmp3, tmp8);
  tmp6 = _mm_xor_si128(tmp6, tmp7);
  tmp10 = _mm_slli_epi32(tmp6, 1);

  tmp3 = _mm_xor_si128(tmp3, tmp10);
  tmp11 = _mm_slli_epi32(tmp6, 2);
  tmp3 = _mm_xor_si128(tmp3, tmp11);
  tmp12 = _mm_slli_epi32(tmp6, 7);
  tmp3 = _mm_xor_si128(tmp3, tmp12);
  *res = _mm_xor_si128(tmp3, tmp6);
};

//Convenience function. Do mul and reduction in one go
static inline void gfmul128_no_refl(__m128i a, __m128i b, __m128i *res) {
  __m128i tmp0, tmp1;

  mul128_karatsuba(a, b, &tmp0, &tmp1);
  gfred128_no_refl(tmp0, tmp1, res);
};

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64. Found at https://github.com/lemire/StronglyUniversalStringHashing/blob/master/include/clmul.h#L233

static inline void mul_64(__m128i a, __m128i b, __m128i* res) {
  *res = _mm_clmulepi64_si128(a, b, 0x00);
}

static inline void gf_red_64(__m128i a, __m128i* res) {
  const __m128i C = _mm_cvtsi64_si128((1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));
  __m128i Q2 = _mm_clmulepi64_si128( a, C, 0x01);
  __m128i Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, 216, 195, 238, 245, 180, 175, 130, 153),
                                _mm_srli_si128(Q2, 8));
  __m128i Q4 = _mm_xor_si128(Q2, a);
  // const __m128i final = _mm_xor_si128(Q3, Q4);
  // return final;/// WARNING: HIGH 64 BITS CONTAIN GARBAGE
  *res = _mm_xor_si128(Q3, Q4);
}

// static inline uint64_t red_64( __m128i a) {
//   return _mm_cvtsi128_si64(gf_red_64(a));
// }

//Convenience function. Do mul and reduction in one go
static inline void gfmul64(__m128i a, __m128i b, __m128i* res) {
  // __m128i tmp0, tmp1;
  mul_64(a, b, res);
  gf_red_64(*res, res);
};

//Functor to be used for mapping global_eval_indices to local indices
class IDMap {
public:
  int mod_base;
  int correction;
  uint32_t* id_mapping;

  IDMap(uint32_t id_mapping[], int mod_base, int correction) : id_mapping(id_mapping), mod_base(mod_base), correction(correction) { }

  void GetExecIDAndIndex(int idx, int& res_exec_id, int& res_id) {

    res_exec_id = (id_mapping[idx] - correction) / mod_base;
    res_id = (id_mapping[idx] - correction) % mod_base;
  }
};

static inline void PrintHex(uint8_t value[], int num_bytes) {
  for (int i = 0; i < num_bytes; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << (std::hex) << ((unsigned int) value[i]);
  }
  std::cout << (std::dec) << std::endl;
}

static inline void PrintBin(uint8_t value[], int num_bits) {
  for (int i = 0; i < num_bits; ++i) {
    if (i != 0 && i % CHAR_BIT == 0) {
      cout << " ";
    }
    cout << (unsigned int) GetBit(i, value);
  }
  cout << endl;
}

static inline void Print128(__m128i val) {
  uint8_t tmp[CSEC_BYTES];
  _mm_storeu_si128((__m128i *) tmp, val);
  PrintHex(tmp, CSEC_BYTES);
}

//Constructs work_size / buffer_size iterations where the last iteration will contain more workload than the rest
static inline void PartitionBufferFixedNum(std::vector<int>& from, std::vector<int>& to, int num_cpus, int work_size) {
  int work_pr_thread = work_size / num_cpus;
  int remaining_work = work_size % num_cpus;
  // For thread index debugging
  // std::cout << "work_size: " << work_size << std::endl;
  // std::cout << "num_cpus: " << num_cpus << std::endl;
  // std::cout << "work_pr_thread: " << work_pr_thread << std::endl;
  // std::cout << "remaining_work: " << remaining_work << std::endl;

  int offset = 0;
  for (int i = 0; i < num_cpus; ++i) {
    int extra_to = 0;
    if (remaining_work > 0) {
      extra_to++;
    }
    from.emplace_back(i * work_pr_thread + offset);
    to.emplace_back(i * work_pr_thread + offset + work_pr_thread + extra_to);
    // std::cout << "Thread" << i << "from:" << from[i] << std::endl;
    // std::cout << "Thread" << i << "to:" << to[i] << std::endl;
    if (remaining_work > 0) {
      offset++;
      remaining_work--;
    }
  }
}

//Constructs work_size / buffer_size + 1 iterations where the last iteration will not contain full workload
static inline void PartitionBufferDynNum(std::vector<int>& from, std::vector<int>& to, int buffer_size, int work_size) {
  int num_iterations = work_size / buffer_size;
  int work_last_iteration = work_size % buffer_size;
  // For thread index debugging
  // std::cout << "work_size: " << work_size << std::endl;
  // std::cout << "num_cpus: " << num_cpus << std::endl;
  // std::cout << "work_pr_thread: " << work_pr_thread << std::endl;
  // std::cout << "remaining_work: " << remaining_work << std::endl;

  for (int i = 0; i < num_iterations; ++i) {
    from.emplace_back(i * buffer_size);
    to.emplace_back(i * buffer_size + buffer_size);
    // std::cout << "Thread" << i << "from:" << from[i] << std::endl;
    // std::cout << "Thread" << i << "to:" << to[i] << std::endl;
  }
  if (work_last_iteration > 0) {
    from.emplace_back(num_iterations * buffer_size);
    to.emplace_back(num_iterations * buffer_size + work_last_iteration);
  }
}

static inline size_t bits_in_byte( uint8_t val) {
  static int const half_byte[] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

  int result1 = half_byte[val & 0x0f];
  int result2 = half_byte[(val >> 4) & 0x0f];

  return result1 + result2;
}

static inline int countSetBits( void* ptr, int start, int end) {
  uint8_t*    first;
  uint8_t*    last;
  int         bits_first;
  int         bits_last;
  uint8_t     mask_first;
  uint8_t     mask_last;

  size_t count = 0;

  // get bits from the first byte
  first = ((uint8_t*) ptr) + (start / 8);
  bits_first = 8 - start % 8;
  mask_first = (1 << bits_first) - 1;
  mask_first = mask_first << (8 - bits_first);


  // get bits from last byte
  last = ((uint8_t*) ptr) + (end / 8);
  bits_last = 1 + (end % 8);
  mask_last = (1 << bits_last) - 1;

  if (first == last) {
    // we only have a range of bits in  the first byte
    count = bits_in_byte( (*first) & mask_first & mask_last);
  }
  else {
    // handle the bits from the first and last bytes specially
    count += bits_in_byte((*first) & mask_first);
    count += bits_in_byte((*last) & mask_last);

    // now we've collected the odds and ends from the start and end of the bit range
    // handle the full bytes in the interior of the range

    for (first = first + 1; first != last; ++first) {
      count += bits_in_byte(*first);
    }
  }

  return count;
}

static inline void transpose_320_128(uint8_t* matrix_array_src, uint8_t* matrix_array_dst, int col_num) {
  //First do the initial transposes
  CBitVector matrix[3];
  int col_mul_matrix_128_bytes = col_num * (128 * 128 / 8);
  int matrix_64_bytes = col_num * (64 * 64 / 8);
  matrix[0].AttachBuf(matrix_array_src, col_mul_matrix_128_bytes);
  matrix[1].AttachBuf(matrix_array_src + col_mul_matrix_128_bytes, col_mul_matrix_128_bytes);
  matrix[2].AttachBuf(matrix_array_src + 2 * col_mul_matrix_128_bytes, 2 * col_num * matrix_64_bytes);

  matrix[0].EklundhBitTranspose(128, col_num * 128);
  matrix[1].EklundhBitTranspose(128, col_num * 128);
  matrix[2].EklundhBitTranspose(64, 2 * col_num * 64);

  int lim = col_num * 128;
  for (int i = 0; i < lim; ++i) {
    std::copy(matrix_array_src + i * 16, matrix_array_src + i * 16 + 16, matrix_array_dst + i * 40);
    std::copy(matrix_array_src + col_mul_matrix_128_bytes + i * 16, matrix_array_src + col_mul_matrix_128_bytes + i * 16 + 16, matrix_array_dst + 16 + i * 40);
    std::copy(matrix_array_src + 2 * col_mul_matrix_128_bytes + i * 8, matrix_array_src + 2 * col_mul_matrix_128_bytes + i * 8 + 8, matrix_array_dst + 32 + i * 40);
  }
}

static inline void transpose_64_128(uint8_t* matrix_array_src, int col_num) {
  CBitVector matrix;
  int col_mul_matrix_64x128_bytes = col_num * (64 * 128 / 8);
  matrix.AttachBuf(matrix_array_src, col_mul_matrix_64x128_bytes);
  matrix.EklundhBitTranspose(64, col_num * 128);
}

static inline void transpose_128_64(uint8_t* matrix_array_src, int col_num) {
  CBitVector matrix;
  int col_mul_matrix_64x128_bytes = col_num * (64 * 128 / 8);
  matrix.AttachBuf(matrix_array_src, col_mul_matrix_64x128_bytes);
  matrix.EklundhBitTranspose(col_num * 128, 64);
}

static inline void transpose_128_320(uint8_t* matrix_array_src, uint8_t* matrix_array_dst, int col_num) {
  //First do the initial transposes
  int col_mul_matrix_128_bytes = col_num * (128 * 128 / 8);
  int matrix_64_bytes = 64 * 64 / 8;

  int lim = col_num * 128;
  for (int i = 0; i < lim; ++i) {
    std::copy(matrix_array_src + i * 40, matrix_array_src + i * 40 + 16, matrix_array_dst + i * 16);
    std::copy(matrix_array_src + 16 + i * 40, matrix_array_src + 16 + i * 40 + 16, matrix_array_dst + col_mul_matrix_128_bytes + i * 16);
    std::copy(matrix_array_src + 32 + i * 40, matrix_array_src + 32 + i * 40 + 8, matrix_array_dst + 2 * col_mul_matrix_128_bytes + i * 8);
  }

  CBitVector matrix[3];
  matrix[0].AttachBuf(matrix_array_dst, col_mul_matrix_128_bytes);
  matrix[1].AttachBuf(matrix_array_dst + col_mul_matrix_128_bytes, col_mul_matrix_128_bytes);
  matrix[2].AttachBuf(matrix_array_dst + 2 * col_mul_matrix_128_bytes, 2 * col_num * matrix_64_bytes);

  matrix[0].EklundhBitTranspose(col_num * 128, 128);
  matrix[1].EklundhBitTranspose(col_num * 128, 128);
  matrix[2].EklundhBitTranspose(2 * col_num * 64, 64);
}

// static inline void transpose_320_64(uint8_t* matrix_array, int col_num) {
//   int matrix_64_bytes = 64 * 64 / 8;
//   CBitVector matrix;
//   matrix.AttachBuf(matrix_array, 5 * col_num * matrix_64_bytes);
//   matrix.EklundhBitTranspose(5 * 64, col_num * 64);
// }

static inline int SampleAndRemove(std::vector<int>& vec, crypto& crypt) {
  //Sample random index
  uint32_t idx;
  crypt.gen_rnd_uniform(&idx, vec.size());
  int res = vec[idx];

  std::swap(vec[idx], vec.back());
  vec.pop_back();

  return res;
}

static inline void GenUniform(PRNG& rnd, uint32_t to, uint32_t& res) {
  //pad to multiple of 4 bytes for uint32_t length
  uint32_t nrndbytes = PAD_TO_MULTIPLE(CSEC + ceil_log2(to), sizeof(uint32_t));
  uint64_t bitsint = (CHAR_BIT * sizeof(uint32_t));
  uint32_t rnditers = CEIL_DIVIDE(nrndbytes * CHAR_BIT, bitsint);

  uint32_t rndbuf[nrndbytes];
  rnd.GenRnd((uint8_t*) rndbuf, nrndbytes);

  uint64_t tmpval = 0;
  for (uint32_t i = 0; i < rnditers; i++) {
    tmpval = (((uint64_t) (tmpval << bitsint)) | ((uint64_t)rndbuf[i]));
    tmpval %= to;
  }
  res = (uint32_t) tmpval;
}

static inline void PermuteArray(uint32_t array[], int size, crypto& crypt) {

  uint32_t tmpidx;
  for (int i = 0; i < size; ++i) {
    crypt.gen_rnd_uniform(&tmpidx, size - i);
    std::swap(array[i], array[i + tmpidx]);
  }
}

static inline void PermuteArray(uint32_t array[], int size, uint8_t seed[]) {
  uint32_t tmpidx;
  std::unique_ptr<uint64_t[]> randomness(new uint64_t[size]);
  PRNG rnd;
  rnd.SetSeed(seed);
  rnd.GenRnd((uint8_t*) randomness.get(), size * sizeof(uint64_t));
  for (int i = 0; i < size; ++i) {
    tmpidx = randomness[i] % (size - i);
    std::swap(array[i], array[i + tmpidx]);
  }
}


//File I/O
static inline void WriteFile(std::string file_name, uint8_t* data, uint32_t num_bytes) {

  ofstream out_file(file_name, ios::out | ios::binary);
  int num_iterations = num_bytes / WRITE_BUFFER_SIZE;
  int work_last_iteration = num_bytes % WRITE_BUFFER_SIZE;

  //write num_iterations * WRITE_BUFFER_SIZE bytes
  for (int i = 0; i < num_iterations; ++i) {
    out_file.write((const char*) data + i * WRITE_BUFFER_SIZE, WRITE_BUFFER_SIZE);
  }
  //Write any remaining bytes
  out_file.write((const char*) data + num_iterations * WRITE_BUFFER_SIZE, work_last_iteration);

  out_file.close();
}

static inline void OverWriteFile(std::string file_name, uint32_t pos, uint8_t* data, uint32_t num_bytes) {

  fstream out_file(file_name, ios::out | ios::in | ios::binary);
  int num_iterations = num_bytes / WRITE_BUFFER_SIZE;
  int work_last_iteration = num_bytes % WRITE_BUFFER_SIZE;
  out_file.seekp(pos, std::ios::beg);

  //write num_iterations * WRITE_BUFFER_SIZE bytes
  for (int i = 0; i < num_iterations; ++i) {
    out_file.write((const char*) data + i * WRITE_BUFFER_SIZE, WRITE_BUFFER_SIZE);
  }
  //Write any remaining bytes
  out_file.write((const char*) data + num_iterations * WRITE_BUFFER_SIZE, work_last_iteration);

  out_file.close();
}

static inline void ReadFile(std::string file_name, uint8_t* data, uint32_t num_bytes) {

  ifstream in_file(file_name, ios::in | ios::binary);
  int num_iterations = num_bytes / READ_BUFFER_SIZE;
  int work_last_iteration = num_bytes % READ_BUFFER_SIZE;

  //read num_iterations * READ_BUFFER_SIZE bytes
  for (int i = 0; i < num_iterations; ++i) {
    in_file.read((char*) data + i * READ_BUFFER_SIZE, READ_BUFFER_SIZE);
  }
  //Write any remaining bytes
  in_file.read((char*) data + num_iterations * READ_BUFFER_SIZE, work_last_iteration);

  in_file.close();
}

static inline int gcd(int a, int b) {
  a = std::abs(a);
  b = std::abs(b);
  while (b != 0) {
    tie(a, b) = std::make_tuple(b, a % b);
  }
  return a;
}

static inline int lcm(int a, int b) {
  int c = gcd(a, b);
  return c == 0 ? 0 : a / c * b;
}

static inline uint32_t nChoosek(uint32_t n, uint32_t k) {
  if (k > n) return 0;
  if (k * 2 > n) /*return*/ k = n - k; //remove the commented section
  if (k == 0) return 1;

  uint32_t result = n;
  for (int i = 2; i <= k; ++i) {
    result *= (n - i + 1);
    result /= i;
  }
  return result;
}

#endif /* DUPLO_UTIL_UTIL_H_ */