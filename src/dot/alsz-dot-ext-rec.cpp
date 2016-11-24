#include "dot/alsz-dot-ext-rec.h"

ALSZDOTExtRec::ALSZDOTExtRec(CommonTools& common_tools) :
  ALSZDOTExt(common_tools),
  receiver((crypto*) &common_tools.crypt, net.rcvthread, net.sndthread, num_seed_OT, num_check_OT) {
}

void ALSZDOTExtRec::InitOTReceiver() {

  receiver.ComputeBaseOTs(m_eFType);

  //Write the BaseOTs to file RECEIVER_BASE_OT_FILENAME. Writes the OT-strings 8 byte counter.
  int OT_keys_size = num_snd_vals * AES_BYTES * num_seed_OT;

  std::vector<uint8_t> ot_tmp_buffer(OT_keys_size + sizeof(uint64_t));
  
  std::copy(receiver.keyBuf, receiver.keyBuf + OT_keys_size, ot_tmp_buffer.data());

  WriteFile(RECEIVER_BASE_OT, ot_tmp_buffer.data(), OT_keys_size + sizeof(uint64_t));

  //Safe to free this now
  free(receiver.keyBuf);
}

void ALSZDOTExtRec::Receive(int num_OT, uint8_t response[], uint8_t choices[]) {
  
  if (num_OT > 256 * NUMOTBLOCKS) {
    throw std::runtime_error("Abort, code cannot handle this many OTs. Recompile with larger NUMOTBLOCKS value.");
  }

  //Super hack. OTX wont work on too small inputs. Tests show it's machine dependent.
  int tmp_num_OT;
  if ((std::thread::hardware_concurrency() == AWS_MACHINE_CORES) && (num_OT < AWS_MACHINE_MIN_OTX)) {
    tmp_num_OT = AWS_MACHINE_MIN_OTX;
  } else if ((std::thread::hardware_concurrency() == LLAN_MACHINE_CORES) && (num_OT < LLAN_MACHINE_MIN_OTX)) {
    tmp_num_OT = LLAN_MACHINE_MIN_OTX;
  } else {
    tmp_num_OT = num_OT;
  }

  CBitVector response_inner, choices_inner;
  response_inner.Create(tmp_num_OT, bit_length_inner);
  choices_inner.Create(tmp_num_OT, (crypto*) &common_tools.crypt);

  //Load the BaseOTs
  int OT_keys_size = num_snd_vals * AES_BYTES * num_seed_OT;
  std::vector<uint8_t> ot_read_buffer(OT_keys_size + sizeof(uint64_t));

  ReadFile(RECEIVER_BASE_OT, ot_read_buffer.data(), OT_keys_size + sizeof(uint64_t));

  OT_AES_KEY_CTX* tmpkeybuf = new OT_AES_KEY_CTX[num_snd_vals * num_seed_OT]; //Do not delete, m_tBaseOTChoices takes ownership
  receiver.InitPRFKeys(tmpkeybuf, ot_read_buffer.data(), num_snd_vals * num_seed_OT);

  receiver.m_tBaseOTKeys.clear();
  receiver.m_tBaseOTKeys.push_back(tmpkeybuf);
  uint8_t* counter_pointer = ot_read_buffer.data() + OT_keys_size;
  receiver.m_nCounter = *(uint64_t*) counter_pointer;

  // Execute OT receiver routine
  auto OTX_begin = GET_TIME();
  receiver.receive(tmp_num_OT, bit_length_inner, num_snd_vals, &choices_inner, &response_inner, s_type, r_type, num_OT_threads, m_fMaskFct.get());
  auto OTX_end = GET_TIME();

  //Then apply privacy amplification to response thus going from bit-strings of length k+2s to k. Can be k+s to k, but then we need so many checks in OTX that it takes longer than doing s more BaseOTs.
  auto privamp_begin = GET_TIME();
  PrivacyAmplification(num_OT, response_inner.GetArr(), response);
  std::copy(choices_inner.GetArr(), choices_inner.GetArr() + BITS_TO_BYTES(num_OT), choices);
  auto privamp_end = GET_TIME();

  //Update offline counter
  OverWriteFile(RECEIVER_BASE_OT, OT_keys_size, (uint8_t*) &receiver.m_nCounter, sizeof(uint64_t));

  //Cleanup
  response_inner.delCBitVector();
  choices_inner.delCBitVector();
#ifdef TINYLOUD
  PRINT_TIME(OTX_end, OTX_begin, "OTX");
  PRINT_TIME(privamp_end, privamp_begin, "PRIVAMP");
#endif
}

void ALSZDOTExtRec::PrivacyAmplification(int num_OT, uint8_t response_inner[], uint8_t response[]) {
  //First receive the random seed from the constructor.
  std::unique_ptr<uint8_t[]> priv_amp_seed(std::make_unique<uint8_t[]>(CSEC_BYTES));
  common_tools.chan.ReceiveBlocking(priv_amp_seed.get(), CSEC_BYTES);

  int byte_length_outer = BITS_TO_BYTES(bit_length_outer);
  uint8_t priv_amp_matrix[bit_length_inner * byte_length_outer];
  GeneratePrivAmpMatrix(priv_amp_seed.get(), priv_amp_matrix, bit_length_inner * byte_length_outer);

  ALSZDOTExt::PrivacyAmplification(priv_amp_matrix, byte_length_outer, bit_length_inner, num_OT, response_inner, response);
}