#include "test.h"

#include "circuit/circuit.h"
#include "util/util.h"

TEST(GetCircuit, Parse) {
  Circuit c = read_text_circuit("test/data/AES-non-expanded.txt");

  FILE *fileptr[2];
  uint8_t *buffer[2];
  long filelen[2];

  fileptr[0] = fopen("test/data/aes_input_0.bin", "rb");  // Open the file in binary mode
  fileptr[1] = fopen("test/data/aes_expected_0.bin", "rb");  // Open the file in binary mode
  fseek(fileptr[0], 0, SEEK_END);          // Jump to the end of the file
  fseek(fileptr[1], 0, SEEK_END);          // Jump to the end of the file
  filelen[0] = ftell(fileptr[0]);             // Get the current byte offset in the file
  filelen[1] = ftell(fileptr[1]);             // Get the current byte offset in the file
  rewind(fileptr[0]);                      // Jump back to the beginning of the file
  rewind(fileptr[1]);                      // Jump back to the beginning of the file

  buffer[0] = new uint8_t[(filelen[0] + 1) * sizeof(uint8_t)]; // Enough memory for file + \0
  buffer[1] = new uint8_t[(filelen[1] + 1) * sizeof(uint8_t)]; // Enough memory for file + \0
  fread(buffer[0], filelen[0], 1, fileptr[0]); // Read in the entire file
  fread(buffer[1], filelen[1], 1, fileptr[1]); // Read in the entire file
  fclose(fileptr[0]); // Close the file
  fclose(fileptr[1]); // Close the file

  std::vector<uint8_t> input(c.num_inp_wires);
  //Read input the right way!
  for (int i = 0; i < c.num_inp_wires; ++i) {
    input[i] = GetBitReversed(i, buffer[0]);
  }

  std::vector<uint8_t> res = eval_circuit(c, input);
  uint8_t res_revesed[16] = { 0 };
  for (int i = 0; i < c.num_out_wires; ++i) {
    SetBitReversed(i, GetBit(i, res.data()), res_revesed);
  }

  ASSERT_TRUE(std::equal(res_revesed, res_revesed + BITS_TO_BYTES(c.num_out_wires), buffer[1]));
}

TEST(GetCircuit, CompareAES) {
  Circuit c = read_text_circuit("test/data/AES-non-expanded.txt");
  Circuit c_new = read_text_circuit("test/data/duplo/aes.wir.GC_bristol");

  std::vector<uint8_t> input(c.num_inp_wires);

  std::vector<uint8_t> res = eval_circuit(c, input);
  std::vector<uint8_t> res_new = eval_circuit(c_new, input);

  uint8_t res_revesed[16] = { 0 };
  uint8_t res_revesed_new[16] = { 0 };
  for (int i = 0; i < c.num_out_wires; ++i) {
    SetBitReversed(i, GetBit(i, res.data()), res_revesed);
    SetBit(i, GetBit(i, res_new.data()), res_revesed_new);
  }

  PrintBin(res_revesed, 128);
  PrintBin(res_revesed_new, 128);

  // ASSERT_TRUE(std::equal(res_revesed, res_revesed + BITS_TO_BYTES(c.num_out_wires), buffer[1]));
}