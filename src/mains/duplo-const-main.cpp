#include "mains/mains.h"
#include "duplo/duplo-constructor.h"

int main(int argc, const char* argv[]) {
  ezOptionParser opt;

  opt.overview = "DuploConstructor Passing Parameters Guide.";
  opt.syntax = "Duploconst first second third forth fifth sixth";
  opt.example = "Duploconst -n 4 -c aes -e 8,2,1 -o 0 -ip 10.11.100.216 -p 28001\n\n";
  opt.footer = "ezOptionParser 0.1.4  Copyright (C) 2011 Remik Ziemlinski\nThis program is free and without warranty.\n";

  opt.add(
    "", // Default.
    0, // Required?
    0, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Display usage instructions.", // Help description.
    "-h",     // Flag token.
    "-help",  // Flag token.
    "--help", // Flag token.
    "--usage" // Flag token.
  );

  opt.add(
    default_num_iters.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Number of circuits to produce and evaluate.", // Help description.
    "-n"
  );

  opt.add(
    default_circuit_name.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Circuit name. Can be either aes, sha-1, sha-256 or cbc.", // Help description.
    "-c" // Flag token.
  );

  opt.add(
    default_execs.c_str(), // Default.
    0, // Required?
    3, // Number of args expected.
    ',', // Delimiter if expecting multiple args.
    "Number of parallel executions for each phase. Preprocessing, Offline and Online.", // Help description.
    "-e"
  );

  opt.add(
    default_optimize_online.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Optimize for online or overall efficiency", // Help description.
    "-o"
  );

  opt.add(
    default_ip_address.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "IP Address of Machine running TinyConst", // Help description.
    "-ip"
  );

  opt.add(
    default_port.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Port to listen on/connect to", // Help description.
    "-p"
  );

  //Attempt to parse input
  opt.parse(argc, argv);

  //Check if help was requested and do some basic validation
  if (opt.isSet("-h")) {
    Usage(opt);
    return 1;
  }
  std::vector<std::string> badOptions;
  if (!opt.gotExpected(badOptions)) {
    for (int i = 0; i < badOptions.size(); ++i)
      std::cerr << "ERROR: Got unexpected number of arguments for option " << badOptions[i] << ".\n\n";
    Usage(opt);
    return 1;
  }

  //Copy inputs into the right variables
  int num_iters, num_execs_components, num_execs_auths, num_execs_online, optimize_online, port;
  std::vector<int> num_execs;
  std::string circuit_name, ip_address, exec_name;
  Circuit circuit;
  // FILE* fileptr;
  // uint8_t* input_buffer;
  // long filelen;
  opt.get("-n")->getInt(num_iters);
  opt.get("-c")->getString(circuit_name);
  circuit_name = "const_" + circuit_name;

  opt.get("-e")->getInts(num_execs);
  num_execs_components = num_execs[0];
  num_execs_auths = num_execs[1];
  num_execs_online = num_execs[2];

  opt.get("-o")->getInt(optimize_online);
  opt.get("-ip")->getString(ip_address);
  opt.get("-p")->getInt(port);

  //Set the circuit variables according to circuit_name
  if (circuit_name.find("aes") != std::string::npos) {
    exec_name = "AES";
    circuit = read_text_circuit("test/data/AES-non-expanded.txt");
    // fileptr = fopen("test/data/aes_input_0.bin", "rb");
  } else if (circuit_name.find("sha-256") != std::string::npos) {
    exec_name = "SHA-256";
    circuit = read_text_circuit("test/data/sha-256.txt");
    // fileptr = fopen("test/data/sha256_input_0.bin", "rb");
  } else if (circuit_name.find("sha-1") != std::string::npos) {
    exec_name = "SHA-1";
    circuit = read_text_circuit("test/data/sha-1.txt");
    // fileptr = fopen("test/data/sha1_input_0.bin", "rb");
  } else if (circuit_name.find("cbc") != std::string::npos) {
    exec_name = "AES-CBC-MAC";
    circuit = read_text_circuit("test/data/aescbcmac16.txt");
    // fileptr = fopen("test/data/cbc_input_0.bin", "rb");
  } else if (circuit_name.find("and") != std::string::npos) {
    exec_name = "AND";
    circuit = read_text_circuit("test/data/and.txt");
    // fileptr = fopen("test/data/cbc_input_0.bin", "rb");
  } else if (circuit_name.find("add32") != std::string::npos) {
    exec_name = "ADD32";
    circuit = read_text_circuit("test/data/adder_32bit.txt");
    // fileptr = fopen("test/data/cbc_input_0.bin", "rb");
  } else if (circuit_name.find("add64") != std::string::npos) {
    exec_name = "ADD64";
    circuit = read_text_circuit("test/data/adder_64bit.txt");
    // fileptr = fopen("test/data/cbc_input_0.bin", "rb");
  } else if (circuit_name.find("mul32") != std::string::npos) {
    exec_name = "MUL32";
    circuit = read_text_circuit("test/data/mult_32x32.txt");
    // fileptr = fopen("test/data/cbc_input_0.bin", "rb");
  } else {
    std::cout << "No such circuit" << std::endl;
    return 1;
  }

  //Read input from file to input_buffer and then set it to const_input
  // fseek(fileptr, 0, SEEK_END);
  // filelen = ftell(fileptr);
  // rewind(fileptr);
  // input_buffer = new uint8_t[(filelen + 1)];
  // fread(input_buffer, filelen, 1, fileptr);

  // std::unique_ptr<uint8_t[]> const_input(std::make_unique<uint8_t[]>(BITS_TO_BYTES(circuit.num_const_inp_wires)));
  // //Read input the "right" way
  // for (int i = 0; i < circuit.num_const_inp_wires; ++i) {
  //   if (GetBitReversed(i, input_buffer)) {
  //     SetBit(i, 1, const_input.get());
  //   } else {
  //     SetBit(i, 0, const_input.get());
  //   }
  // }

  //Compute the required number of common_tools that are to be created. We create one main param and one for each sub-thread that will be spawned later on. Need to know this at this point to setup context properly

  int max_num_parallel_execs = max_element(num_execs.begin(), num_execs.end())[0];

  zmq::context_t context(NUM_IO_THREADS, 2 * (max_num_parallel_execs + 1)); //We need two sockets pr. channel

  //Setup the main common_tools object
  CommonTools common_tools(constant_seeds[0], ip_address, (uint16_t) port, 0, context, GLOBAL_PARAMS_CHAN);

  uint8_t* dummy_val = new uint8_t[network_dummy_size]; //50 MB
  uint8_t* dummy_val2 = new uint8_t[network_dummy_size]; //50 MB
  common_tools.chan.ReceiveBlocking(dummy_val2, network_dummy_size);
  common_tools.chan.Send(dummy_val, network_dummy_size);

  mr_init_threading(); //Needed for Miracl library to work with threading.
  DuploConstructor duplo_const(common_tools, max_num_parallel_execs);

  //Run initial Setup (BaseOT) phase
  auto setup_begin = GET_TIME();
  duplo_const.Setup();
  auto setup_end = GET_TIME();

  mr_end_threading();

  //Run Preprocessing phase
  auto preprocess_begin = GET_TIME();
  duplo_const.PreprocessComponentType(circuit_name, circuit, num_iters, num_execs_components);
  auto preprocess_end = GET_TIME();

  std::vector<std::pair<std::string, uint32_t>> pairs;
  std::vector<std::vector<uint8_t>> inputs;
  std::vector<BYTEArrayVector> output_keys(num_iters);
  for (int i = 0; i < num_iters; ++i) {
    pairs.emplace_back(std::make_pair(circuit_name, i));
    inputs.emplace_back(std::vector<uint8_t>(BITS_TO_BYTES(circuit.num_const_inp_wires)));
  }

  //Run Auth Preprocessing phase
  auto prepare_eval_begin = GET_TIME();
  duplo_const.PrepareComponents(pairs, num_execs_auths);
  auto prepare_eval_end = GET_TIME();

  auto eval_circuits_begin = GET_TIME();
  duplo_const.EvalComponents(pairs, inputs, output_keys, num_execs_online);
  auto eval_circuits_end = GET_TIME();

  std::vector<std::vector<uint8_t>> outputs(num_iters);
  auto decode_keys_begin = GET_TIME();
  duplo_const.DecodeKeys(pairs, output_keys, outputs, num_execs_online);
  auto decode_keys_end = GET_TIME();

  // Average out the timings of each phase and print results
  uint64_t setup_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(setup_end - setup_begin).count();
  uint64_t preprocess_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(preprocess_end - preprocess_begin).count();
  uint64_t prepare_eval_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(prepare_eval_end - prepare_eval_begin).count();

  uint64_t eval_circuits_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(eval_circuits_end - eval_circuits_begin).count();
  uint64_t decode_keys_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(decode_keys_end - decode_keys_begin).count();

  std::cout << "Setup ms: " << (double) setup_time_nano / num_iters / 1000000 << std::endl;
  std::cout << "Circuit Preprocess ms: " << (double) preprocess_time_nano / num_iters / 1000000 << std::endl;
  std::cout << "PrepareEval Preprocess ms: " << (double) prepare_eval_time_nano / num_iters / 1000000 << std::endl;
  std::cout << "Eval circuits ms: " << (double) eval_circuits_nano / num_iters / 1000000 << std::endl;
  std::cout << "Decode keys ms: " << (double) decode_keys_nano / num_iters / 1000000 << std::endl;
}