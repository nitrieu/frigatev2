#ifndef DUPLO_CIRCUIT_CIRCUIT_H_
#define DUPLO_CIRCUIT_CIRCUIT_H_

#include "util/util.h"

//The below enum is coupled with the gate_constants_array array, if the enum of a gate is changed here it needs to be changed there as well
enum GATE {
	AND  = 0,
	NAND = 1,
	OR   = 2,
	NOR  = 3,
	XOR  = 4,
	NXOR = 5,
	NOT  = 6
};

class Gate {
public:
	uint32_t left_wire;
	uint32_t right_wire;
	uint32_t out_wire;
	enum GATE type;
};

class Circuit {
public:
	std::vector<Gate> gates;
	uint32_t num_wires = 0;

	uint32_t num_const_inp_wires = 0;
	uint32_t num_eval_inp_wires = 0;
	uint32_t num_inp_wires = 0;

	uint32_t const_inp_wires_start = 0;
	uint32_t const_inp_wires_stop = 0;

	int32_t eval_inp_wires_start = 0;
	int32_t eval_inp_wires_stop = 0;

	uint32_t const_out_wires_start = 0;
	uint32_t const_out_wires_stop = 0;

	int32_t eval_out_wires_start = 0;
	int32_t eval_out_wires_stop = 0;

	uint32_t num_const_out_wires = 0;
	int32_t num_eval_out_wires = 0;
	uint32_t num_out_wires = 0;
	uint32_t out_wires_start = 0;

	uint32_t num_non_free_gates = 0;
	uint32_t num_gates = 0;
	uint32_t idxCircuit = 0;
};

static std::vector<uint8_t> eval_circuit(Circuit& circuit, std::vector<uint8_t> input) {

	std::vector<uint8_t> evals(circuit.num_wires);
	for (int i = 0; i < circuit.num_inp_wires; ++i) {
		evals[i] = input[i];
	}

	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == AND) {
			evals[g.out_wire] = evals[g.left_wire] & evals[g.right_wire];
		} else if (g.type == NAND) {
			evals[g.out_wire] = !(evals[g.left_wire] & evals[g.right_wire]);
		} else if (g.type == OR) {
			evals[g.out_wire] = evals[g.left_wire] | evals[g.right_wire];
		} else if (g.type == NOR) {
			evals[g.out_wire] = !(evals[g.left_wire] | evals[g.right_wire]);
		} else if (g.type == XOR) {
			evals[g.out_wire] = evals[g.left_wire] ^ evals[g.right_wire];
		} else if (g.type == NXOR) {
			evals[g.out_wire] = !(evals[g.left_wire] ^ evals[g.right_wire]);
		} else if (g.type == NOT) {
			evals[g.out_wire] = !evals[g.left_wire];
		} else {
			std::cout << "error evaluating circuit" << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	std::cout << circuit.out_wires_start << std::endl;
	//Go from bytes to bits
	std::vector<uint8_t> eval_res_bits(BITS_TO_BYTES(circuit.num_out_wires));
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		SetBit(i, evals[circuit.out_wires_start + i], eval_res_bits.data());
	}

	return eval_res_bits;
}

class ComposedCircuit {
public:
	ComposedCircuit() {}
	ComposedCircuit(uint32_t num_inp_circuits, uint32_t num_out_circuits, uint32_t num_layers)
		: num_inp_circuits(num_inp_circuits)
		, num_out_circuits(num_out_circuits)
		, circuits_in_layer(num_layers) {

	}

	uint32_t num_inp_circuits = 0;
	uint32_t num_out_circuits = 0;
	std::vector<std::vector<uint32_t>> circuits_in_layer;

	std::vector<std::pair<std::string, uint32_t>> circuits;

	std::vector<Circuit> functions;
	std::vector<uint32_t> num_circuit_copies;

	std::vector<std::vector<std::pair<uint32_t, std::vector<uint32_t>>>> out_wire_holders;

	std::unordered_map<uint32_t, uint32_t>  out_wire_holder_to_wire_idx;


	uint32_t num_inp_wires = 0;
	uint32_t num_out_wires = 0;
	uint32_t num_wires = 0;
	uint32_t num_layers = 0;
	uint32_t num_functions = 0;
	uint32_t num_components = 0;

	uint32_t num_eval_inp_wires = 0;
	uint32_t num_eval_out_wires = 0;

	uint32_t num_const_inp_wires = 0;
	uint32_t num_const_out_wires = 0;

	uint32_t out_wires_start = 0;
	uint32_t const_out_wires_start = 0;
	uint32_t eval_out_wires_start = 0;

};

Circuit ParseCircuit(char* data);

Circuit DuploIdentityCircuit(uint32_t num_const_inp_wires, uint32_t num_eval_inp_wires);
Circuit DuploParseCircuit(char raw_circuit[]);
ComposedCircuit ParseComposedCircuit(char* data, std::string circuits_prefix = "");

Circuit read_text_circuit(const char* circuit_file);
//read circuit from frigate format
//The wires are ordered so that the first n1 wires correspond to the first input value, the next n2 wires correspond to the second input value. The next n3 wires correspond to the output of the circuit.
ComposedCircuit read_text_composed_circuit(const char* circuit_file, std::string circuits_prefix = ""); //each circuit contains each function of the program



#endif /* DUPLO_CIRCUIT_CIRCUIT_H_ */