#include "dot/alsz-dot-ext-snd.h"

ALSZDOTExtSnd::ALSZDOTExtSnd(CommonTools& common_tools, bool set_lsb_delta) :
  ALSZDOTExt(common_tools),
  set_lsb_delta(set_lsb_delta),
  sender(ALSZOTExtSnd((crypto*) &common_tools.crypt, net.rcvthread, net.sndthread, num_seed_OT, num_check_OT)) {
}

void ALSZDOTExtSnd::InitOTSender() {

  sender.ComputeBaseOTs(m_eFType);

  //Write the BaseOTs to file SENDER_BASE_OT. Writes the OT-strings, choice bits and finally 8 byte counter.
  int OT_keys_size = AES_BYTES * num_seed_OT;
  int OT_choices_size = BITS_TO_BYTES(num_seed_OT);

  uint8_t* OT_choices = sender.m_tBaseOTChoices[0]->GetArr();

  std::vector<uint8_t> ot_tmp_buffer(OT_keys_size + OT_choices_size + sizeof(uint64_t));

  std::copy(sender.keyBuf, sender.keyBuf + OT_keys_size, ot_tmp_buffer.data());
  std::copy(OT_choices, OT_choices + OT_choices_size, ot_tmp_buffer.data() + OT_keys_size);
  WriteFile(SENDER_BASE_OT, ot_tmp_buffer.data(), OT_keys_size + OT_choices_size + sizeof(uint64_t));

  //Safe to free this now
  free(sender.keyBuf);

}

void ALSZDOTExtSnd::Send(int num_OT, uint8_t base[], uint8_t delta[]) {
  
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

  //Cannot use unique_ptr due to interface of OTX
  CBitVector** X = new CBitVector*[num_snd_vals]; //Ownership is passed on to sender, so it gets deleted when sender is deleted.
  X[0] = new CBitVector();
  X[1] = new CBitVector();

  X[0]->Create(tmp_num_OT * bit_length_inner);
  X[1]->Create(tmp_num_OT * bit_length_inner);

  //Load the BaseOTs
  int OT_keys_size = AES_BYTES * num_seed_OT;
  int OT_choices_size = BITS_TO_BYTES(num_seed_OT);
  
  // std::unique_ptr<uint8_t[]> ot_read_buffer(std::make_unique<uint8_t[]>(OT_keys_size + OT_choices_size + sizeof(uint64_t)));
  std::vector<uint8_t> ot_read_buffer(OT_keys_size + OT_choices_size + sizeof(uint64_t));

  CBitVector* base_ot_choices = new CBitVector(num_seed_OT); //Do not delete, m_tBaseOTChoices takes ownership
  OT_AES_KEY_CTX* tmpkeybuf = new OT_AES_KEY_CTX[num_seed_OT]; //Do not delete, m_tBaseOTChoices takes ownership
  
  ReadFile(SENDER_BASE_OT, ot_read_buffer.data(), OT_keys_size + OT_choices_size + sizeof(uint64_t));
  std::copy(ot_read_buffer.data() + OT_keys_size, ot_read_buffer.data() + OT_keys_size + OT_choices_size, base_ot_choices->GetArr());

  sender.InitPRFKeys(tmpkeybuf, ot_read_buffer.data(), num_seed_OT);

  sender.m_tBaseOTKeys.clear();
  sender.m_tBaseOTChoices.clear();
  sender.m_tBaseOTKeys.push_back(tmpkeybuf);
  sender.m_tBaseOTChoices.push_back(base_ot_choices);

  uint8_t* counter_pointer = ot_read_buffer.data() + OT_keys_size + OT_choices_size;
  sender.m_nCounter = *(uint64_t*) counter_pointer;


  // Execute OT sender routine
  auto OTX_begin = GET_TIME();
  sender.send(tmp_num_OT, bit_length_inner, num_snd_vals, X, s_type, r_type, num_OT_threads, m_fMaskFct.get());
  auto OTX_end = GET_TIME();

  //Post OTX processing
  int byte_length_inner = BITS_TO_BYTES(bit_length_inner);
  uint8_t delta_inner[byte_length_inner];

  std::copy(X[1]->GetArr(), X[1]->GetArr() + byte_length_inner, delta_inner);
  XOR_UINT8_T(delta_inner, X[0]->GetArr(), byte_length_inner);

  //Then apply privacy amplification to vectors and delta thus going from bit-strings of length k+s to k. Can be k+s to k, but then we need so many checks in OTX that it takes longer than doing s more BaseOTs.
  auto privamp_begin = GET_TIME();
  PrivacyAmplification(num_OT, X[0]->GetArr(), delta_inner, base, delta);
  auto privamp_end = GET_TIME();

  //Update offline OT counter
  OverWriteFile(SENDER_BASE_OT, OT_keys_size + OT_choices_size, (uint8_t*) &sender.m_nCounter, sizeof(uint64_t));


  X[0]->delCBitVector();
  X[1]->delCBitVector();
  delete X[0];
  delete X[1];

#ifdef TINYLOUD
  PRINT_TIME(OTX_end, OTX_begin, "OTX");
  PRINT_TIME(privamp_end, privamp_begin, "PRIVAMP");
#endif
}

void ALSZDOTExtSnd::PrivacyAmplification(int num_OT, uint8_t base_inner[], uint8_t delta_inner[], uint8_t base[], uint8_t delta[]) {

  int byte_length_outer = BITS_TO_BYTES(bit_length_outer);
  uint8_t priv_amp_seed[CSEC_BYTES];
  uint8_t priv_amp_matrix[bit_length_inner * byte_length_outer];

  bool done = false;
  std::fill(delta, delta + CSEC_BYTES, 0);
  while (!done) {
    common_tools.crypt.gen_rnd(priv_amp_seed, CSEC_BYTES);
    GeneratePrivAmpMatrix(priv_amp_seed, priv_amp_matrix, bit_length_inner * byte_length_outer);
    for (int bit = 0; bit < bit_length_inner; ++bit) {
      if (GetBitReversed(bit, delta_inner)) {
        XOR_128(delta, priv_amp_matrix + (bit * byte_length_outer));
      }
    }
    //If set_lsb_delta flag is set, this ensures that lsb(delta) == 1. This is needed for Half-Gate garbling.
    if (set_lsb_delta && (GetLSB(delta) != 1)) {
      //Reset delta_out as we're going to go into the loop again
      std::fill(delta, delta + CSEC_BYTES, 0);
    } else {
      //We exit loop
      done = true;
    }
  }
  common_tools.chan.Send(priv_amp_seed, CSEC_BYTES);

  ALSZDOTExt::PrivacyAmplification(priv_amp_matrix, byte_length_outer, bit_length_inner, num_OT, base_inner, base);
}