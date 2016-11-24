#include "circuit/circuit.h"
using namespace std;

//The input and output indices should be considered offsets to 0 and circuit.out_wires_start, respectively
void SetCircuitOffsetIndices(Circuit& circuit) {

  //Set Inputs
  circuit.num_inp_wires = circuit.num_const_inp_wires + circuit.num_eval_inp_wires;

  circuit.const_inp_wires_start = 0;
  circuit.const_inp_wires_stop = circuit.const_inp_wires_start + circuit.num_const_inp_wires;

  circuit.eval_inp_wires_start = circuit.const_inp_wires_stop;
  circuit.eval_inp_wires_stop = circuit.eval_inp_wires_start + circuit.num_eval_inp_wires;

  //Set Outputs
  circuit.const_out_wires_start = 0;
  circuit.const_out_wires_stop = circuit.const_out_wires_start + circuit.num_const_out_wires;

  circuit.eval_out_wires_start =  circuit.num_out_wires - circuit.num_eval_out_wires;
  circuit.eval_out_wires_stop =  circuit.eval_out_wires_start + circuit.num_eval_out_wires;
}

void SetComposedCircuitOffsetIndices(ComposedCircuit& composed_circuit) {

  composed_circuit.num_inp_wires = composed_circuit.num_eval_inp_wires + composed_circuit.num_const_inp_wires;
  composed_circuit.num_out_wires = composed_circuit.num_const_out_wires + composed_circuit.num_eval_out_wires;

  composed_circuit.out_wires_start = composed_circuit.num_inp_wires; //not an offset!

  composed_circuit.const_out_wires_start = composed_circuit.num_inp_wires;
  composed_circuit.eval_out_wires_start = composed_circuit.num_out_wires - composed_circuit.num_eval_out_wires;
}

void AddOutputIdentityGates(Circuit& circuit) {
  //Add identity AND-gates to all output wires. This is to simplify DUPLO evaluation as now it is easy to identify which output wire needs to be leaked for the evalutator to decode the output.
  uint32_t org_num_wires = circuit.num_wires;
  uint32_t org_out_start = circuit.out_wires_start;
  circuit.out_wires_start = org_num_wires;
  for (uint32_t i = 0; i < circuit.num_out_wires; ++i) {
    circuit.gates.emplace_back(Gate());
    circuit.gates[circuit.num_gates].type = AND;
    circuit.gates[circuit.num_gates].left_wire = org_out_start + i;
    circuit.gates[circuit.num_gates].right_wire = org_out_start + i;
    circuit.gates[circuit.num_gates].out_wire = org_num_wires + i;

    ++circuit.num_gates;
    ++circuit.num_non_free_gates;
    ++circuit.num_wires;
  }
}

void ParseGates(Circuit& circuit, char raw_circuit[], char terminate_char) {
  uint32_t num_inputs, left_wire_idx, right_wire_idx, out_wire_idx;
  char type[4];

  while (*raw_circuit != terminate_char) {
    if (*raw_circuit == '\n') {
      raw_circuit = strchr(raw_circuit, '\n') + 1;
      continue;
    }
    num_inputs = (uint32_t) atoi(raw_circuit);
    raw_circuit = strchr(raw_circuit,  ' ') + 1;
    raw_circuit = strchr(raw_circuit,  ' ') + 1; //We skip num_output wires as they all have 1.

    if (num_inputs == 1) {
      left_wire_idx = (uint32_t) atoi(raw_circuit);
      raw_circuit = strchr(raw_circuit,  ' ') + 1;
      out_wire_idx = (uint32_t) atoi(raw_circuit);
      raw_circuit = strchr(raw_circuit,  ' ') + 1;
      raw_circuit = strchr(raw_circuit,  '\n') + 1;
      circuit.gates.emplace_back(Gate());
      circuit.gates[circuit.num_gates].type = NOT;
      circuit.gates[circuit.num_gates].left_wire = left_wire_idx;
      circuit.gates[circuit.num_gates].out_wire = out_wire_idx;

      ++circuit.num_gates;
    } else {
      left_wire_idx = (uint32_t) atoi(raw_circuit);
      raw_circuit = strchr(raw_circuit,  ' ') + 1;
      right_wire_idx = (uint32_t) atoi(raw_circuit);
      raw_circuit = strchr(raw_circuit,  ' ') + 1;
      out_wire_idx = (uint32_t) atoi(raw_circuit);

      raw_circuit = strchr(raw_circuit,  ' ') + 1;

      memcpy(type, raw_circuit, 4 * sizeof(char));
      std::string type_string(type);
      raw_circuit = strchr(raw_circuit,  '\n') + 1;

      //Do not change the order of these if statements, they matter as eg. AND is substring of NAND
      if (type_string.find("NAND") != std::string::npos) {
        circuit.gates.emplace_back(Gate());
        circuit.gates[circuit.num_gates].type = NAND;
        circuit.gates[circuit.num_gates].left_wire = left_wire_idx;
        circuit.gates[circuit.num_gates].right_wire = right_wire_idx;
        circuit.gates[circuit.num_gates].out_wire = out_wire_idx;

        ++circuit.num_gates;
        ++circuit.num_non_free_gates;
      } else if (type_string.find("AND") != std::string::npos) {
        circuit.gates.emplace_back(Gate());
        circuit.gates[circuit.num_gates].type = AND;
        circuit.gates[circuit.num_gates].left_wire = left_wire_idx;
        circuit.gates[circuit.num_gates].right_wire = right_wire_idx;
        circuit.gates[circuit.num_gates].out_wire = out_wire_idx;

        ++circuit.num_gates;
        ++circuit.num_non_free_gates;
      } else if ((type_string.find("NXOR") != std::string::npos) ||
                 (type_string.find("XNOR") != std::string::npos)) {
        circuit.gates.emplace_back(Gate());
        circuit.gates[circuit.num_gates].type = NXOR;
        circuit.gates[circuit.num_gates].left_wire = left_wire_idx;
        circuit.gates[circuit.num_gates].right_wire = right_wire_idx;
        circuit.gates[circuit.num_gates].out_wire = out_wire_idx;

        ++circuit.num_gates;
      } else if (type_string.find("XOR") != std::string::npos) {
        circuit.gates.emplace_back(Gate());
        circuit.gates[circuit.num_gates].type = XOR;
        circuit.gates[circuit.num_gates].left_wire = left_wire_idx;
        circuit.gates[circuit.num_gates].right_wire = right_wire_idx;
        circuit.gates[circuit.num_gates].out_wire = out_wire_idx;

        ++circuit.num_gates;
      } else if (type_string.find("NOR") != std::string::npos) {
        circuit.gates.emplace_back(Gate());
        circuit.gates[circuit.num_gates].type = NOR;
        circuit.gates[circuit.num_gates].left_wire = left_wire_idx;
        circuit.gates[circuit.num_gates].right_wire = right_wire_idx;
        circuit.gates[circuit.num_gates].out_wire = out_wire_idx;

        ++circuit.num_gates;
        ++circuit.num_non_free_gates;
      } else if (type_string.find("OR") != std::string::npos) {
        circuit.gates.emplace_back(Gate());
        circuit.gates[circuit.num_gates].type = OR;
        circuit.gates[circuit.num_gates].left_wire = left_wire_idx;
        circuit.gates[circuit.num_gates].right_wire = right_wire_idx;
        circuit.gates[circuit.num_gates].out_wire = out_wire_idx;

        ++circuit.num_gates;
        ++circuit.num_non_free_gates;
      } else {
        std::cout << "cannot parse gate of type: " << type_string << std::endl;
        exit(EXIT_FAILURE);
      }
    }
  }
}

//Parse the gate description given a char array of the description file.
Circuit ParseCircuit(char raw_circuit[]) {
  Circuit circuit;
  raw_circuit = strchr(raw_circuit, ' ') + 1; //we dont need num_gates
  circuit.num_wires = (uint32_t) atoi(raw_circuit);
  raw_circuit = strchr(raw_circuit, ' ') + 1;
  circuit.out_wires_start = (uint32_t) atoi(raw_circuit);
  raw_circuit = strchr(raw_circuit,  '\n') + 1; //Skip to next line

  circuit.num_const_inp_wires = (uint32_t) atoi(raw_circuit);
  raw_circuit = strchr(raw_circuit, ' ') + 1;
  circuit.num_eval_inp_wires = (uint32_t) atoi(raw_circuit);


  raw_circuit = strchr(raw_circuit, ' ') + 1;
  circuit.num_out_wires = (uint32_t) atoi(raw_circuit);
  raw_circuit = strchr(raw_circuit, ' ') + 1;
  circuit.num_const_out_wires = (uint32_t) atoi(raw_circuit);
  raw_circuit = strchr(raw_circuit, ' ') + 1;
  circuit.num_eval_out_wires = (uint32_t) atoi(raw_circuit);

  raw_circuit = strchr(raw_circuit,  '\n') + 1; //Skip to next line
  raw_circuit = strchr(raw_circuit,  '\n') + 1; //Skip to next line

  circuit.num_gates = 0;
  circuit.num_non_free_gates = 0;

  ParseGates(circuit, raw_circuit, EOF);

  SetCircuitOffsetIndices(circuit);
  AddOutputIdentityGates(circuit);

  return circuit;
}

Circuit DuploIdentityCircuit(uint32_t num_const_inp_wires, uint32_t num_eval_inp_wires) {
  Circuit circuit;
  circuit.idxCircuit = 0;

  circuit.num_const_inp_wires = num_const_inp_wires;
  circuit.num_eval_inp_wires = num_eval_inp_wires;
  circuit.num_inp_wires = circuit.num_const_inp_wires + circuit.num_eval_inp_wires;

  circuit.num_const_out_wires = 0; //As the circuit is evaluated on eval side all identity output keys should be delivered to evaluator for further evaluation
  circuit.num_eval_out_wires = circuit.num_inp_wires;

  circuit.num_out_wires = circuit.num_inp_wires; //must be set before SetCircuitOffsetIndices call

  circuit.num_wires = circuit.num_inp_wires; //currently only input wires exist

  circuit.num_gates = 0;
  circuit.num_non_free_gates = 0;
  circuit.out_wires_start = 0;
  SetCircuitOffsetIndices(circuit);
  AddOutputIdentityGates(circuit);

  return circuit;
}

//Parse the gate description given a char array of the description file.
Circuit DuploParseCircuit(char raw_circuit[]) {
  Circuit circuit;

  raw_circuit = strchr(raw_circuit, ' ') + 1; //skip FN
  circuit.idxCircuit = (uint32_t) atoi(raw_circuit);

  raw_circuit = strchr(raw_circuit, ' ') + 1; //#number num_inp_wires
  circuit.num_inp_wires = (uint32_t) atoi(raw_circuit);
  circuit.num_const_inp_wires = circuit.num_inp_wires;

  circuit.out_wires_start = circuit.num_inp_wires;

  //All intermediate circuits are interpreted as const owns all input and output wires. It doesn't matter for duplo evaluation
  circuit.num_eval_inp_wires = 0;
  circuit.num_eval_out_wires = 0;

  raw_circuit = strchr(raw_circuit, ' ') + 1; //#number num_out_wires
  circuit.num_out_wires = (uint32_t) atoi(raw_circuit);
  circuit.num_const_out_wires = circuit.num_out_wires;

  raw_circuit = strchr(raw_circuit, ' ') + 1; // #number total wires
  circuit.num_wires = (uint32_t) atoi(raw_circuit);

  raw_circuit = strchr(raw_circuit, '\n') + 1; //Skip this line

  circuit.num_gates = 0;
  circuit.num_non_free_gates = 0;

  ParseGates(circuit, raw_circuit, '-');
  SetCircuitOffsetIndices(circuit);
  AddOutputIdentityGates(circuit);

  return circuit;
}

ComposedCircuit ParseComposedCircuit(char raw_circuit[], std::string circuits_prefix) {

  ComposedCircuit composed_circuit;

  composed_circuit.num_functions = (uint32_t) atoi(raw_circuit); //get number functions

  raw_circuit = strchr(raw_circuit, ' ') + 1;
  composed_circuit.num_layers = (uint32_t) atoi(raw_circuit) + 1; //plus 1 for identity circuit

  raw_circuit = strchr(raw_circuit, ' ') + 1;
  composed_circuit.num_components = (uint32_t) atoi(raw_circuit) + 1; //plus 1 for identity circuit

  raw_circuit = strchr(raw_circuit, '\n') + 1; //next line
  composed_circuit.num_const_inp_wires = (uint32_t) atoi(raw_circuit);

  raw_circuit = strchr(raw_circuit, ' ') + 1;
  composed_circuit.num_eval_inp_wires = (uint32_t) atoi(raw_circuit);

  raw_circuit = strchr(raw_circuit, ' ') + 1;
  composed_circuit.num_const_out_wires = (uint32_t) atoi(raw_circuit);

  raw_circuit = strchr(raw_circuit, ' ') + 1;
  composed_circuit.num_eval_out_wires = (uint32_t) atoi(raw_circuit);

  raw_circuit = strchr(raw_circuit, '\n') + 1; //skip rest of line
  raw_circuit = strchr(raw_circuit, '\n') + 1; //skip entire empty line

  SetComposedCircuitOffsetIndices(composed_circuit);

  //create identity circuit with index FN 0
  composed_circuit.functions.emplace_back(DuploIdentityCircuit(composed_circuit.num_const_inp_wires, composed_circuit.num_eval_inp_wires));

  /////////////////////read each function!!!//////////////////////
  uint32_t num_functions = composed_circuit.num_functions - 1; //we do not count main function
  for (int i = 0; i < num_functions; i++) {
    composed_circuit.functions.emplace_back(DuploParseCircuit(raw_circuit));
    raw_circuit = strchr(raw_circuit, '-') + 1; //next function
    raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
    raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
  }


  raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line FN main

  composed_circuit.out_wire_holders.resize(composed_circuit.num_components);
  composed_circuit.num_circuit_copies.resize(composed_circuit.functions.size());
  composed_circuit.circuits_in_layer.resize(composed_circuit.num_layers);

  //We put exactly 1 circuit in each layer
  for (int i = 0; i < composed_circuit.num_layers; ++i) {
    composed_circuit.circuits_in_layer[i].emplace_back(i);
  }

  std::unordered_map<uint32_t, std::vector<uint32_t>> holder_to_global_inp_wires;
  std::unordered_map<uint32_t, std::vector<uint32_t>> holder_to_global_out_wires;
  std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> global_out_wire_to_holder;
  std::unordered_map<uint32_t, uint32_t> unique_non_out_wires;

  //Add 1 Identity circuit and populate maps
  composed_circuit.num_inp_circuits = 1;
  composed_circuit.circuits.emplace_back(
    std::make_pair(circuits_prefix +
                   to_string(composed_circuit.functions[0].idxCircuit),
                   composed_circuit.num_circuit_copies[0]));
  ++composed_circuit.num_circuit_copies[0];

  composed_circuit.out_wire_holder_to_wire_idx.emplace(0, composed_circuit.out_wires_start);

  std::vector<uint32_t> identity_ins_and_outs(composed_circuit.functions[0].num_inp_wires);

  std::iota(std::begin(identity_ins_and_outs), std::end(identity_ins_and_outs), 0);
  holder_to_global_inp_wires.emplace(0, identity_ins_and_outs);

  std::iota(std::begin(identity_ins_and_outs), std::end(identity_ins_and_outs), composed_circuit.functions[0].out_wires_start);
  holder_to_global_out_wires.emplace(0, identity_ins_and_outs);

  for (int i = 0; i < identity_ins_and_outs.size(); ++i) {
    global_out_wire_to_holder.emplace(composed_circuit.out_wires_start + i, std::make_pair(0, i));
  }

  for (int i = 0; i < composed_circuit.num_inp_wires; ++i) {
    unique_non_out_wires.emplace(i, 1);
    unique_non_out_wires.emplace(composed_circuit.num_inp_wires + i, 1);
  }

  //Parse function calls and populate maps in the process
  uint32_t intermediate_wires_start = composed_circuit.out_wires_start + composed_circuit.num_out_wires;
  uint32_t curr_function = 1; //starts at 1 due to identity circuit
  while (*raw_circuit != EOF) {
    if (*raw_circuit == '\n') {
      raw_circuit = strchr(raw_circuit, '\n') + 1;
      continue;
    }

    //Add function call to circuit and increment num_circuit_copies
    raw_circuit = strchr(raw_circuit, ' ') + 1; //FN i
    uint32_t function_id = (uint32_t) atoi(raw_circuit);
    composed_circuit.circuits.emplace_back(
      std::make_pair(circuits_prefix +
                     to_string(composed_circuit.functions[function_id].idxCircuit),
                     composed_circuit.num_circuit_copies[function_id]));
    ++composed_circuit.num_circuit_copies[function_id];

    raw_circuit = strchr(raw_circuit, '\n') + 1; //input wire list
    std::vector<uint32_t> inputs;
    while (*raw_circuit != '\n') { //run through input list

      uint32_t global_in_wire = (uint32_t) atoi(raw_circuit) + composed_circuit.out_wires_start; // increment due to identity circuit
      inputs.emplace_back(global_in_wire);

      raw_circuit = strchr(raw_circuit, ' ') + 1;
    }
    holder_to_global_inp_wires.emplace(curr_function, inputs);

    std::unordered_map<uint32_t, std::vector<uint32_t>> out_holder_info;
    std::vector<std::vector<uint32_t>> insert_order;
    for (int i = 0; i < inputs.size(); ++i) {
      uint32_t out_holder_num = std::get<0>(global_out_wire_to_holder[inputs[i]]);
      uint32_t out_holder_wire_num = std::get<1>(global_out_wire_to_holder[inputs[i]]);

      if (out_holder_info.find(out_holder_num) == out_holder_info.end()) {
        out_holder_info.emplace(out_holder_num, std::vector<uint32_t>());
        insert_order.emplace_back(std::vector<uint32_t>());
      }
      out_holder_info[out_holder_num].emplace_back(out_holder_wire_num);
      insert_order[insert_order.size() - 1].emplace_back(out_holder_num);
    }

    for (int i = 0; i < out_holder_info.size(); ++i) {
      composed_circuit.out_wire_holders[curr_function].emplace_back(std::make_pair(insert_order[i][0], out_holder_info[insert_order[i][0]]));
    }


    raw_circuit = strchr(raw_circuit, '\n') + 1; //output wire list
    std::vector<uint32_t> outputs;
    while (*raw_circuit != '\n') { //run through output list

      uint32_t global_out_wire = (uint32_t) atoi(raw_circuit);
      if (global_out_wire < intermediate_wires_start) { //It's an output wire so we shift the global_out_wire with unique_non_out_wires.size() to put it at the end of all wires. This means we follow convention of output wires being the ones with highest value
        global_out_wire += (unique_non_out_wires.size() - composed_circuit.out_wires_start + 1);

      } else { //it's an intermediate wire and we just increment it with the identity wires added. We also add the wire to the unique_non_out_wires map
        global_out_wire += composed_circuit.out_wires_start;
        unique_non_out_wires.emplace(global_out_wire, 1);
      }
      outputs.emplace_back(global_out_wire);

      raw_circuit = strchr(raw_circuit, ' ') + 1;
    }
    holder_to_global_out_wires.emplace(curr_function, outputs);

    composed_circuit.out_wire_holder_to_wire_idx.emplace(curr_function, outputs[0]);

    for (int i = 0; i < outputs.size(); ++i) {
      //overwrites if necessary, which is needed if wires are reused
      global_out_wire_to_holder[outputs[i]] = std::make_pair(curr_function, i);
    }

    ++curr_function;

    raw_circuit = strchr(raw_circuit, '\n') + 1;
    raw_circuit = strchr(raw_circuit, '\n') + 1;
  }

  //Set the final fields

  composed_circuit.num_wires = unique_non_out_wires.size() + composed_circuit.num_out_wires;

  for (int i = 0; i < composed_circuit.num_out_wires; i += composed_circuit.functions[composed_circuit.functions.size() - 1 - i].num_out_wires) {
    ++composed_circuit.num_out_circuits; //composed_circuit.num_out_circuits is initialized to 0
  }

  return composed_circuit;
}

//Reads circuit in textual format. Writes byte length of text file to file_size.
Circuit read_text_circuit(const char* circuit_file) {
  FILE* file;
  size_t file_size;
  file = fopen(circuit_file, "r");
  if (file == NULL) {
    printf("ERROR: Could not open text circuit: %s\n", circuit_file);
    exit(EXIT_FAILURE);
  }
  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  rewind(file);

  std::unique_ptr<char[]> data(new char[file_size + 1]);
  size_t size = fread(data.get(), 1, file_size, file);
  if (size != file_size) {
    printf("ERROR while loading file: %s\n", circuit_file);
    exit(EXIT_FAILURE);
  }
  data[file_size] = EOF;
  if (ferror(file)) {
    printf("ERROR: fread() error\n");
    exit(EXIT_FAILURE);
  }
  fclose(file);
  Circuit circuit = ParseCircuit(data.get());

  return circuit;

}

ComposedCircuit read_text_composed_circuit(const char* circuit_file, std::string circuits_prefix) {
  FILE* file;
  size_t file_size;
  file = fopen(circuit_file, "r");
  if (file == NULL) {
    printf("ERROR: Could not open text circuit: %s\n", circuit_file);
    exit(EXIT_FAILURE);
  }
  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  rewind(file);

  std::unique_ptr<char[]> data(new char[file_size + 1]);
  size_t size = fread(data.get(), 1, file_size, file);
  if (size != file_size) {
    printf("ERROR while loading file from frigate: %s\n", circuit_file);
    exit(EXIT_FAILURE);
  }
  data[file_size] = EOF;
  if (ferror(file)) {
    printf("ERROR: fread() error\n");
    exit(EXIT_FAILURE);
  }
  fclose(file);
  ComposedCircuit circuit = ParseComposedCircuit(data.get(), circuits_prefix);


  return circuit;
}

