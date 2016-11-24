#include "test-duplo.h"

TEST_F(TestDuplo, AESCorrectness) {
  mr_init_threading();
  Circuit circuit = read_text_circuit("test/data/AES-non-expanded.txt");

  std::string const_circuit("const_aes");
  std::string eval_circuit("eval_aes");

  uint32_t num_iters = 30;

  //Read input from file to input_buffer and then set it to const_input
  FILE* const_fileptr = fopen("test/data/aes_input_0.bin", "rb");
  uint8_t* const_input_buffer;
  long const_filelen;
  fseek(const_fileptr, 0, SEEK_END);
  const_filelen = ftell(const_fileptr);
  rewind(const_fileptr);
  const_input_buffer = new uint8_t[(const_filelen + 1)];
  fread(const_input_buffer, const_filelen, 1, const_fileptr);

  std::vector<uint8_t> const_input(BITS_TO_BYTES(circuit.num_const_inp_wires));
  //Read input the "right" way
  for (int i = 0; i < circuit.num_const_inp_wires; ++i) {
    if (GetBitReversed(i, const_input_buffer)) {
      SetBit(i, 1, const_input.data());
    } else {
      SetBit(i, 0, const_input.data());
    }
  }
  fclose(const_fileptr);

  std::vector<std::vector<uint8_t>> const_outputs(num_iters);
  std::future<void> ret_const = std::async(std::launch::async, [this, &circuit, &const_circuit, &const_input, &const_outputs, num_iters]() {
    duplo_const.Setup();
    duplo_const.PreprocessComponentType(const_circuit, circuit, num_iters, num_execs_components);

    std::vector<std::pair<std::string, uint32_t>> pairs;
    std::vector<std::vector<uint8_t>> inputs;
    std::vector<BYTEArrayVector> output_keys(num_iters);
    for (int i = 0; i < num_iters; ++i) {
      pairs.emplace_back(std::make_pair(const_circuit, i));
      inputs.emplace_back(const_input);
    }

    duplo_const.PrepareComponents(pairs, num_execs_auths);

    duplo_const.EvalComponents(pairs, inputs, output_keys, num_execs_online);
    duplo_const.DecodeKeys(pairs, output_keys, const_outputs, num_execs_online);
  });

  FILE* eval_fileptr[2];
  eval_fileptr[0] = fopen("test/data/aes_input_0.bin", "rb");
  eval_fileptr[1] = fopen("test/data/aes_expected_0.bin", "rb");
  uint8_t* eval_buffer[2];
  long eval_filelen[2];
  fseek(eval_fileptr[0], 0, SEEK_END);
  fseek(eval_fileptr[1], 0, SEEK_END);
  eval_filelen[0] = ftell(eval_fileptr[0]);
  eval_filelen[1] = ftell(eval_fileptr[1]);
  rewind(eval_fileptr[0]);
  rewind(eval_fileptr[1]);

  eval_buffer[0] = new uint8_t[(eval_filelen[0] + 1)];
  eval_buffer[1] = new uint8_t[(eval_filelen[1] + 1)];
  fread(eval_buffer[0], eval_filelen[0], 1, eval_fileptr[0]);
  fread(eval_buffer[1], eval_filelen[1], 1, eval_fileptr[1]);

  std::vector<uint8_t> eval_input(BITS_TO_BYTES(circuit.num_eval_inp_wires));
  for (int i = 0; i < circuit.num_eval_inp_wires; ++i) {
    if (GetBitReversed(i, eval_buffer[0]  + BITS_TO_BYTES(circuit.num_const_inp_wires))) {
      SetBit(i, 1, eval_input.data());
    } else {
      SetBit(i, 0, eval_input.data());
    }
  }
  uint8_t* expected_output = eval_buffer[1];
  fclose(eval_fileptr[0]);
  fclose(eval_fileptr[1]);


  std::vector<std::vector<uint8_t>> eval_outputs(num_iters);
  std::future<void> ret_eval = std::async(std::launch::async, [this, &circuit, &eval_circuit, &eval_input, &eval_outputs, num_iters]() {
    duplo_eval.Setup();
    duplo_eval.PreprocessComponentType(eval_circuit, circuit, num_iters, num_execs_components);

    std::vector<std::pair<std::string, uint32_t>> pairs;
    std::vector<std::vector<uint8_t>> inputs;
    std::vector<BYTEArrayVector> output_keys(num_iters);
    for (int i = 0; i < num_iters; ++i) {
      pairs.emplace_back(std::make_pair(eval_circuit, i));
      inputs.emplace_back(eval_input);
    }

    duplo_eval.PrepareComponents(pairs, num_execs_auths);

    duplo_eval.EvalComponents(pairs, inputs, output_keys, num_execs_online);
    duplo_eval.DecodeKeys(pairs, output_keys, eval_outputs, num_execs_online);

  });

  ret_const.wait();
  ret_eval.wait();
  mr_end_threading();

  bool all_success = true;
  for (int i = 0; i < num_iters; ++i) {
    for (int j = 0; j < circuit.num_out_wires; ++j) {
      if (j < circuit.const_out_wires_stop) {
        if (GetBitReversed(circuit.const_out_wires_start + j, expected_output) != GetBit(j, const_outputs[i].data())) {
          all_success = false;
        }
      }

      if ((j >= circuit.eval_out_wires_start) &&
          (j <  circuit.eval_out_wires_stop)) {
        uint32_t curr_bit_pos = j - circuit.eval_out_wires_start;
        if (GetBitReversed(circuit.eval_out_wires_start + curr_bit_pos, expected_output) != GetBit(curr_bit_pos, eval_outputs[i].data())) {
          all_success = false;
        }
      }
    }
  }
  ASSERT_TRUE(all_success);
}