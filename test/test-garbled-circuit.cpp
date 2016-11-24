#include "test.h"

#include "garbling/garbling-handler.h"

void TestCircuit(Circuit& circuit, FILE* fileptr[]) {
  uint8_t *buffer[2];
  long filelen[2];
  fseek(fileptr[0], 0, SEEK_END);          // Jump to the end of the file
  fseek(fileptr[1], 0, SEEK_END);          // Jump to the end of the file
  filelen[0] = ftell(fileptr[0]);             // Get the current byte offset in the file
  filelen[1] = ftell(fileptr[1]);             // Get the current byte offset in the file
  rewind(fileptr[0]);                      // Jump back to the beginning of the file
  rewind(fileptr[1]);                      // Jump back to the beginning of the file

  buffer[0] = new uint8_t[(filelen[0] + 1)]; // Enough memory for file + \0
  buffer[1] = new uint8_t[(filelen[1] + 1)]; // Enough memory for file + \0
  fread(buffer[0], filelen[0], 1, fileptr[0]); // Read in the entire file
  fread(buffer[1], filelen[1], 1, fileptr[1]); // Read in the entire file

  uint8_t* input = new uint8_t[BITS_TO_BYTES(circuit.num_inp_wires)];
  //Read input the right way!
  for (int i = 0; i < circuit.num_inp_wires; ++i) {
    if (GetBitReversed(i, buffer[0])) {
      SetBit(i, 1, input);
    } else {
      SetBit(i, 0, input);
    }
  }

  uint8_t* expected_output = buffer[1];

  //////////////////////////////////////////////////////////////////////
  uint32_t num_circuits = 1;
  zmq::context_t context(1);
  CommonTools common_tools(constant_seeds[0], default_ip_address, default_port, 0, context);
  std::vector<GarbledCircuit> garbled_circuits(num_circuits, GarbledCircuit(circuit));

  BYTEArrayVector deltas(num_circuits, CSEC_BYTES);
  common_tools.rnd.GenRnd(deltas.GetArray(), deltas.size);

  BYTEArrayVector input_zero_keys(num_circuits * circuit.num_inp_wires, CSEC_BYTES);
  common_tools.rnd.GenRnd(input_zero_keys.GetArray(), input_zero_keys.size);
  BYTEArrayVector output_zero_keys(num_circuits * circuit.num_out_wires, CSEC_BYTES);

  BYTEArrayVector input_keys(circuit.num_inp_wires, CSEC_BYTES);
  BYTEArrayVector res_output_keys(circuit.num_out_wires, CSEC_BYTES);
  std::vector<std::unique_ptr<uint8_t[]>> output_decryptions;
  std::vector<std::unique_ptr<uint8_t[]>> output_results;

  GarblingHandler gh;
  for (int i = 0; i < num_circuits; ++i) {
    //Init garbled circuit and delta
    SetBit(CSEC - 1, 1, deltas[i]);

    //Garble Circuit
    gh.GarbleCircuit(input_zero_keys[i * circuit.num_inp_wires], output_zero_keys[i * circuit.num_out_wires], deltas[i], garbled_circuits[i]);

    gh.EncodeInput(input_zero_keys[i * circuit.num_inp_wires], deltas[i], input, input_keys.GetArray(), circuit.num_inp_wires);

    //Extract output decoding bits
    output_decryptions.emplace_back(std::make_unique<uint8_t[]>(BITS_TO_BYTES(circuit.num_out_wires)));
    for (int j = 0; j < circuit.num_out_wires; ++j) {
      SetBit(j, GetLSB(output_zero_keys[i * circuit.num_out_wires + j]), output_decryptions[i].get());
    }

    //Init output_results
    output_results.emplace_back(std::make_unique<uint8_t[]>(BITS_TO_BYTES(circuit.num_out_wires)));

    //Eval garbled circuit
    gh.EvalGarbledCircuit(input_keys.GetArray(), circuit, garbled_circuits[i].GetTables(), res_output_keys.GetArray());

    //Decode garbled circuit
    DecodeGarbledOutput(res_output_keys.GetArray(), output_decryptions[i].get(), output_results[i].get(), garbled_circuits[i].circuit.num_out_wires);
    // PrintBin(expected_output, 128);
    // PrintBin(output_results[i].get(), 128);
    //Check if expected_output matches actual output
    for (int j = 0; j < circuit.num_out_wires; ++j) {
      ASSERT_TRUE(GetBitReversed(j, expected_output) == GetBit(j, output_results[i].get()));
    }
  }
}

TEST(GarbledCircuit, AES) {

 Circuit circuit = read_text_circuit("test/data/AES-non-expanded.txt");
	//Circuit circuit = read_text_circuit("test/data/duplo/aes.wir.GC_bristol");
  FILE *fileptr[2];
  fileptr[0] = fopen("test/data/aes_input_0.bin", "rb");  // Open the file in binary mode
  fileptr[1] = fopen("test/data/aes_expected_0.bin", "rb");  // Open the file in binary mode
  TestCircuit(circuit, fileptr);
}

TEST(GarbledCircuit, SHA1) {
  Circuit circuit = read_text_circuit("test/data/sha-1.txt");
  FILE *fileptr[2];
  fileptr[0] = fopen("test/data/sha1_input_0.bin", "rb");  // Open the file in binary mode
  fileptr[1] = fopen("test/data/sha1_expected_0.bin", "rb");  // Open the file in binary mode
  TestCircuit(circuit, fileptr);
}

TEST(GarbledCircuit, SHA256) {
  Circuit circuit = read_text_circuit("test/data/sha-256.txt");
  FILE *fileptr[2];
  fileptr[0] = fopen("test/data/sha256_input_0.bin", "rb");  // Open the file in binary mode
  fileptr[1] = fopen("test/data/sha256_expected_0.bin", "rb");  // Open the file in binary mode
  TestCircuit(circuit, fileptr);
}

TEST(GarbledCircuit, DISABLED_Duplo) {

//	ComposedCircuit circuits = read_text_composed_circuit("test/data/duplo/temp.wir.GC_duplo");	
	// ComposedCircuit circuits = read_text_composed_circuit("test/data/hamming1.wir.dpGC");
}