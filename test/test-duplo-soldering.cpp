#include "test-duplo.h"

void Build2InpAESTo1(ComposedCircuit& composed_circuit, Circuit& circuit, std::string component_type) {

	composed_circuit.circuits_in_layer.resize(2);

	//Add two input circuits to layer 0
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 0));
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 1));
	composed_circuit.circuits_in_layer[0].emplace_back(0); //input circuits go in layer 0
	composed_circuit.circuits_in_layer[0].emplace_back(1); //input circuits go in layer 0

	//Add one output circuit to layer 1
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 2));
	composed_circuit.circuits_in_layer[1].emplace_back(2); //circuit with index 2 go in layer 1. The .emplace_back(2) refers to the index of this circuit in composed_circuit.circuits, not that is to AES circuit with index 2!

	composed_circuit.num_inp_circuits = 2;
	composed_circuit.num_out_circuits = 1;

	composed_circuit.out_wire_holders.resize(composed_circuit.circuits.size());

	//Add output holder info
	std::vector<uint32_t> out_vals(circuit.num_out_wires);
	std::iota(std::begin(out_vals), std::end(out_vals), 0);

	composed_circuit.out_wire_holders[2].emplace_back(std::make_pair(0, out_vals));
	composed_circuit.out_wire_holders[2].emplace_back(std::make_pair(1, out_vals));

	//Add output wire pointers
	composed_circuit.out_wire_holder_to_wire_idx.emplace(0, 2 * circuit.num_inp_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(1, 2 * circuit.num_inp_wires + circuit.num_out_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(2, 2 * circuit.num_inp_wires + 2 * circuit.num_out_wires);
}

std::vector<uint8_t> ComputeBuild2InpAESTo1(Circuit& circuit) {

	//////////////
	std::vector<uint8_t> evals0(circuit.num_wires);
	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals0[g.out_wire] = !evals0[g.left_wire];
		}
		else if (g.type == XOR) {
			evals0[g.out_wire] = evals0[g.left_wire] ^ evals0[g.right_wire];
		}
		else if (g.type == AND) {
			evals0[g.out_wire] = evals0[g.left_wire] & evals0[g.right_wire];
		}
	}

	std::vector<uint8_t> evals1(circuit.num_wires);
	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals1[g.out_wire] = !evals1[g.left_wire];
		}
		else if (g.type == XOR) {
			evals1[g.out_wire] = evals1[g.left_wire] ^ evals1[g.right_wire];
		}
		else if (g.type == AND) {
			evals1[g.out_wire] = evals1[g.left_wire] & evals1[g.right_wire];
		}
	}
	//////////////
	std::vector<uint8_t> evals2(circuit.num_wires);
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		evals2[i] = evals0[circuit.out_wires_start + i];
		evals2[circuit.num_out_wires + i] = evals1[circuit.out_wires_start + i];
	}

	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals2[g.out_wire] = !evals2[g.left_wire];
		}
		else if (g.type == XOR) {
			evals2[g.out_wire] = evals2[g.left_wire] ^ evals2[g.right_wire];
		}
		else if (g.type == AND) {
			evals2[g.out_wire] = evals2[g.left_wire] & evals2[g.right_wire];
		}
	}

	//Go from bytes to bits
	std::vector<uint8_t> eval_res_bits(BITS_TO_BYTES(circuit.num_out_wires));
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		if (evals2[circuit.out_wires_start + i]) {
			SetBit(i, 1, eval_res_bits.data());
		}
		else {
			SetBit(i, 0, eval_res_bits.data());
		}
	}

	return eval_res_bits;
}

void Build2InpAESTo1TwoOutputs(ComposedCircuit& composed_circuit, Circuit& circuit, std::string component_type) {

	composed_circuit.circuits_in_layer.resize(2);

	//Add two input circuits to layer 0
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 0));
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 1));
	composed_circuit.circuits_in_layer[0].emplace_back(0); //input circuits go in layer 0
	composed_circuit.circuits_in_layer[0].emplace_back(1); //input circuits go in layer 0

	//Add one output circuit to layer 1
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 2));
	composed_circuit.circuits_in_layer[1].emplace_back(2); //circuit with index 2 go in layer 1. The .emplace_back(2) refers to the index of this circuit in composed_circuit.circuits, not that is to AES circuit with index 2!

	composed_circuit.num_inp_circuits = 2;
	composed_circuit.num_out_circuits = 2;

	composed_circuit.out_wire_holders.resize(composed_circuit.circuits.size());

	//Add output wire pointers
	composed_circuit.out_wire_holder_to_wire_idx.emplace(0, 2 * circuit.num_inp_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(1, 2 * circuit.num_inp_wires + circuit.num_out_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(2, 2 * circuit.num_inp_wires + 2 * circuit.num_out_wires);

	//Add input wire component info
	std::vector<uint32_t> out_vals(circuit.num_out_wires);
	std::iota(std::begin(out_vals), std::end(out_vals), 0);

	composed_circuit.out_wire_holders[2].emplace_back(std::make_pair(0, out_vals));
	composed_circuit.out_wire_holders[2].emplace_back(std::make_pair(1, out_vals));
}

std::vector<uint8_t> ComputeBuild2InpAESTo1TwoOutputs(Circuit& circuit) {

	//////////////
	std::vector<uint8_t> evals0(circuit.num_wires);
	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals0[g.out_wire] = !evals0[g.left_wire];
		}
		else if (g.type == XOR) {
			evals0[g.out_wire] = evals0[g.left_wire] ^ evals0[g.right_wire];
		}
		else if (g.type == AND) {
			evals0[g.out_wire] = evals0[g.left_wire] & evals0[g.right_wire];
		}
	}

	std::vector<uint8_t> evals1(circuit.num_wires);
	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals1[g.out_wire] = !evals1[g.left_wire];
		}
		else if (g.type == XOR) {
			evals1[g.out_wire] = evals1[g.left_wire] ^ evals1[g.right_wire];
		}
		else if (g.type == AND) {
			evals1[g.out_wire] = evals1[g.left_wire] & evals1[g.right_wire];
		}
	}
	//////////////
	std::vector<uint8_t> evals2(circuit.num_wires);
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		evals2[i] = evals0[circuit.out_wires_start + i];
		evals2[circuit.num_out_wires + i] = evals1[circuit.out_wires_start + i];
	}

	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals2[g.out_wire] = !evals2[g.left_wire];
		}
		else if (g.type == XOR) {
			evals2[g.out_wire] = evals2[g.left_wire] ^ evals2[g.right_wire];
		}
		else if (g.type == AND) {
			evals2[g.out_wire] = evals2[g.left_wire] & evals2[g.right_wire];
		}
	}

	//Go from bytes to bits
	std::vector<uint8_t> eval_res_bits(BITS_TO_BYTES(2 * circuit.num_out_wires));
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		if (evals1[circuit.out_wires_start + i]) {
			SetBit(i, 1, eval_res_bits.data());
		}
		else {
			SetBit(i, 0, eval_res_bits.data());
		}
	}

	//Go from bytes to bits
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		if (evals2[circuit.out_wires_start + i]) {
			SetBit(circuit.num_out_wires + i, 1, eval_res_bits.data());
		}
		else {
			SetBit(circuit.num_out_wires + i, 0, eval_res_bits.data());
		}
	}

	return eval_res_bits;
}

void Build2AESInto2Into1(ComposedCircuit& composed_circuit, Circuit& circuit, std::string component_type) {

	composed_circuit.circuits_in_layer.resize(3);

	//Add two input circuits
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 0));
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 1));
	composed_circuit.circuits_in_layer[0].emplace_back(0); //input circuits go in layer 0
	composed_circuit.circuits_in_layer[0].emplace_back(1); //input circuits go in layer 0

	//Add two circuits to layer 1
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 2));
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 3));
	composed_circuit.circuits_in_layer[1].emplace_back(2); //input circuits go in layer 0
	composed_circuit.circuits_in_layer[1].emplace_back(3); //input circuits go in layer 0

	//Add one output circuit to layer 2
	composed_circuit.circuits.emplace_back(std::make_pair(component_type, 4));
	composed_circuit.circuits_in_layer[2].emplace_back(4); //input circuits go in layer 0

	composed_circuit.num_inp_circuits = 2;
	composed_circuit.num_out_circuits = 1;

	composed_circuit.out_wire_holders.resize(composed_circuit.circuits.size());

	//Add output wire pointers
	composed_circuit.out_wire_holder_to_wire_idx.emplace(0, 2 * circuit.num_inp_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(1, 2 * circuit.num_inp_wires + circuit.num_out_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(2, 2 * circuit.num_inp_wires + 2 * circuit.num_out_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(3, 2 * circuit.num_inp_wires + 3 * circuit.num_out_wires);
	composed_circuit.out_wire_holder_to_wire_idx.emplace(4, 2 * circuit.num_inp_wires + 4 * circuit.num_out_wires);

	//Add input wire component info
	std::vector<uint32_t> out_vals(circuit.num_out_wires);
	std::iota(std::begin(out_vals), std::end(out_vals), 0);

	//2
	composed_circuit.out_wire_holders[2].emplace_back(std::make_pair(0, out_vals));
	composed_circuit.out_wire_holders[2].emplace_back(std::make_pair(1, out_vals));
	//3
	composed_circuit.out_wire_holders[3].emplace_back(std::make_pair(0, out_vals));
	composed_circuit.out_wire_holders[3].emplace_back(std::make_pair(1, out_vals));
	//4
	composed_circuit.out_wire_holders[4].emplace_back(std::make_pair(2, out_vals));
	composed_circuit.out_wire_holders[4].emplace_back(std::make_pair(3, out_vals));
}

std::vector<uint8_t> ComputeBuild2AESInto2Into1(Circuit& circuit) {

	//////////////
	std::vector<uint8_t> evals0(circuit.num_wires);
	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals0[g.out_wire] = !evals0[g.left_wire];
		}
		else if (g.type == XOR) {
			evals0[g.out_wire] = evals0[g.left_wire] ^ evals0[g.right_wire];
		}
		else if (g.type == AND) {
			evals0[g.out_wire] = evals0[g.left_wire] & evals0[g.right_wire];
		}
	}

	std::vector<uint8_t> evals1(circuit.num_wires);
	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals1[g.out_wire] = !evals1[g.left_wire];
		}
		else if (g.type == XOR) {
			evals1[g.out_wire] = evals1[g.left_wire] ^ evals1[g.right_wire];
		}
		else if (g.type == AND) {
			evals1[g.out_wire] = evals1[g.left_wire] & evals1[g.right_wire];
		}
	}
	//////////////
	std::vector<uint8_t> evals2(circuit.num_wires);
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		evals2[i] = evals0[circuit.out_wires_start + i];
		evals2[circuit.num_out_wires + i] = evals1[circuit.out_wires_start + i];
	}

	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals2[g.out_wire] = !evals2[g.left_wire];
		}
		else if (g.type == XOR) {
			evals2[g.out_wire] = evals2[g.left_wire] ^ evals2[g.right_wire];
		}
		else if (g.type == AND) {
			evals2[g.out_wire] = evals2[g.left_wire] & evals2[g.right_wire];
		}
	}

	//////////////
	std::vector<uint8_t> evals3(circuit.num_wires);
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		evals3[i] = evals0[circuit.out_wires_start + i];
		evals3[circuit.num_out_wires + i] = evals1[circuit.out_wires_start + i];
	}

	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals3[g.out_wire] = !evals3[g.left_wire];
		}
		else if (g.type == XOR) {
			evals3[g.out_wire] = evals3[g.left_wire] ^ evals3[g.right_wire];
		}
		else if (g.type == AND) {
			evals3[g.out_wire] = evals3[g.left_wire] & evals3[g.right_wire];
		}
	}

	//////////////
	std::vector<uint8_t> evals4(circuit.num_wires);
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		evals4[i] = evals2[circuit.out_wires_start + i];
		evals4[circuit.num_out_wires + i] = evals3[circuit.out_wires_start + i];
	}

	for (int i = 0; i < circuit.num_gates; ++i) {
		Gate& g = circuit.gates[i];
		if (g.type == NOT) {
			evals4[g.out_wire] = !evals4[g.left_wire];
		}
		else if (g.type == XOR) {
			evals4[g.out_wire] = evals4[g.left_wire] ^ evals4[g.right_wire];
		}
		else if (g.type == AND) {
			evals4[g.out_wire] = evals4[g.left_wire] & evals4[g.right_wire];
		}
	}

	//Go from bytes to bits
	std::vector<uint8_t> eval_res_bits(BITS_TO_BYTES(circuit.num_out_wires));
	for (int i = 0; i < circuit.num_out_wires; ++i) {
		if (evals4[circuit.out_wires_start + i]) {
			SetBit(i, 1, eval_res_bits.data());
		}
		else {
			SetBit(i, 0, eval_res_bits.data());
		}
	}

	return eval_res_bits;
}

TEST_F(TestDuplo, DISABLED_Soldering) {
	mr_init_threading();
	Circuit circuit = read_text_circuit("test/data/AES-non-expanded.txt");
	uint32_t test_id = 2;
	std::string composed_circuit_name("composed_aes");

	std::vector<BYTEArrayVector> const_output_keys;
	std::vector<std::vector<uint8_t>> const_outputs;
	std::future<void> ret_const = std::async(std::launch::async,
	[this, &circuit, &const_output_keys, &composed_circuit_name, &const_outputs, test_id]() {

		std::string circuit_name("const_aes");
		ComposedCircuit composed_circuit;
		if (test_id == 0) {
			Build2InpAESTo1(composed_circuit, circuit, circuit_name);
		}
		else if (test_id == 1) {
			Build2AESInto2Into1(composed_circuit, circuit, circuit_name);
		}
		else if (test_id == 2) {
			Build2InpAESTo1TwoOutputs(composed_circuit, circuit, circuit_name);
		}
		else return;


		duplo_const.Setup();
		duplo_const.PreprocessComponentType(circuit_name, circuit, composed_circuit.circuits.size(), num_execs_components);
		duplo_const.SolderGarbledComponents(composed_circuit_name, composed_circuit, num_execs_components);

		std::vector<std::pair<std::string, uint32_t>> input_circuits;
		for (int c = 0; c < composed_circuit.num_inp_circuits; ++c) {
			input_circuits.emplace_back(composed_circuit.circuits[c]);
		}

		duplo_const.PrepareComponents(input_circuits, num_execs_auths);

		std::vector<std::vector<uint8_t>> inputs;
		for (int i = 0; i < composed_circuit.num_inp_circuits; ++i) {
			inputs.emplace_back(std::vector<uint8_t>(BITS_TO_BYTES(circuit.num_const_inp_wires)));
		}

		duplo_const.EvalComposedComponents(composed_circuit_name, inputs, const_output_keys, num_execs_online);

		std::vector<std::pair<std::string, uint32_t>> output_circuits;
		for (int c = composed_circuit.circuits.size() - composed_circuit.num_out_circuits; c < composed_circuit.circuits.size(); ++c) {
			output_circuits.emplace_back(composed_circuit.circuits[c]);
			const_outputs.emplace_back(std::vector<uint8_t>());
		}

		duplo_const.DecodeKeys(output_circuits, const_output_keys, const_outputs, num_execs_online);
	});

	std::vector<BYTEArrayVector> eval_output_keys;
	std::vector<std::vector<uint8_t>> eval_outputs;
	std::future<void> ret_eval = std::async(std::launch::async,
	[this, &circuit, &eval_output_keys, &composed_circuit_name, &eval_outputs, test_id]() {
		std::string circuit_name("eval_aes");
		ComposedCircuit composed_circuit;
		if (test_id == 0) {
			Build2InpAESTo1(composed_circuit, circuit, circuit_name);
		}
		else if (test_id == 1) {
			Build2AESInto2Into1(composed_circuit, circuit, circuit_name);
		}
		else if (test_id == 2) {
			Build2InpAESTo1TwoOutputs(composed_circuit, circuit, circuit_name);
		}
		else return;

		duplo_eval.Setup();
		duplo_eval.PreprocessComponentType(circuit_name, circuit, composed_circuit.circuits.size(), num_execs_components);
		duplo_eval.SolderGarbledComponents(composed_circuit_name, composed_circuit, num_execs_components);

		std::vector<std::pair<std::string, uint32_t>> input_circuits;
		for (int c = 0; c < composed_circuit.num_inp_circuits; ++c) {
			input_circuits.emplace_back(composed_circuit.circuits[c]);
		}

		duplo_eval.PrepareComponents(input_circuits, num_execs_auths);

		std::vector<std::vector<uint8_t>> inputs;
		for (int i = 0; i < composed_circuit.num_inp_circuits; ++i) {
			inputs.emplace_back(std::vector<uint8_t>(BITS_TO_BYTES(circuit.num_eval_inp_wires)));
		}

		duplo_eval.EvalComposedComponents(composed_circuit_name, inputs, eval_output_keys, num_execs_online);

		std::vector<std::pair<std::string, uint32_t>> output_circuits;
		for (int c = composed_circuit.circuits.size() - composed_circuit.num_out_circuits; c < composed_circuit.circuits.size(); ++c) {
			output_circuits.emplace_back(composed_circuit.circuits[c]);
			eval_outputs.emplace_back(std::vector<uint8_t>());
		}

		duplo_eval.DecodeKeys(output_circuits, eval_output_keys, eval_outputs, num_execs_online);
	});

	ret_const.wait();
	ret_eval.wait();
	mr_end_threading();

	std::vector<uint8_t> correct_res;
	if (test_id == 0) {
		correct_res = ComputeBuild2InpAESTo1(circuit);
	}
	else if (test_id == 1) {
		correct_res = ComputeBuild2AESInto2Into1(circuit);
	}
	else if (test_id == 2) {
		correct_res = ComputeBuild2InpAESTo1TwoOutputs(circuit);
	}

	//Check correctness
	ASSERT_TRUE(std::equal(eval_outputs[0].begin(), eval_outputs[0].begin() + BITS_TO_BYTES(circuit.num_out_wires), const_outputs[0].begin()));
	ASSERT_TRUE(std::equal(correct_res.begin(), correct_res.begin() + BITS_TO_BYTES(circuit.num_out_wires), eval_outputs[0].begin()));
}


TEST_F(TestDuplo, SolderingFrigate) {
	mr_init_threading();
	// std::string filename("test/data/temp.wir.dpGC");
	std::string filename("test/data/hamming.wir.dpGC");
	
	ComposedCircuit const_composed_circuit = read_text_composed_circuit(filename.c_str(), "const");
	std::string const_composed_circuit_name("const_composed_test");

	std::vector<BYTEArrayVector> const_output_keys;
	std::vector<std::vector<uint8_t>> const_outputs;
	std::future<void> ret_const = std::async(std::launch::async,

	[this, &const_output_keys, &const_composed_circuit_name, &const_composed_circuit, &const_outputs]() {

		duplo_const.Setup();
		for (int i = 0; i < const_composed_circuit.functions.size(); ++i) {
			duplo_const.PreprocessComponentType(const_composed_circuit.circuits[i].first, const_composed_circuit.functions[i], const_composed_circuit.num_circuit_copies[i], num_execs_components);
		}
		duplo_const.SolderGarbledComponents(const_composed_circuit_name, const_composed_circuit, num_execs_components);

		std::vector<std::pair<std::string, uint32_t>> input_circuits;
		for (int c = 0; c < const_composed_circuit.num_inp_circuits; ++c) {
			input_circuits.emplace_back(const_composed_circuit.circuits[c]);
		}

		duplo_const.PrepareComponents(input_circuits, num_execs_auths);

		std::vector<std::vector<uint8_t>> inputs;
		for (int i = 0; i < const_composed_circuit.num_inp_circuits; ++i) {
			inputs.emplace_back(std::vector<uint8_t>(BITS_TO_BYTES(const_composed_circuit.functions[i].num_const_inp_wires)));
		}


		duplo_const.EvalComposedComponents(const_composed_circuit_name, inputs, const_output_keys, num_execs_online);

		std::vector<std::pair<std::string, uint32_t>> output_circuits;
		for (int c = const_composed_circuit.circuits.size() - const_composed_circuit.num_out_circuits; c < const_composed_circuit.circuits.size(); ++c) {
			output_circuits.emplace_back(const_composed_circuit.circuits[c]);
			const_outputs.emplace_back(std::vector<uint8_t>());
		}

		duplo_const.DecodeKeys(output_circuits, const_output_keys, const_outputs, num_execs_online);
	});

	ComposedCircuit eval_composed_circuit = read_text_composed_circuit(filename.c_str(), "eval");
	std::string eval_composed_circuit_name("eval_composed_test");

	std::vector<BYTEArrayVector> eval_output_keys;
	std::vector<std::vector<uint8_t>> eval_outputs;
	std::future<void> ret_eval = std::async(std::launch::async,
	[this, &eval_output_keys, &eval_composed_circuit_name, &eval_composed_circuit, &eval_outputs]() {
		duplo_eval.Setup();

		for (int i = 0; i < eval_composed_circuit.functions.size(); ++i) {
			duplo_eval.PreprocessComponentType(eval_composed_circuit.circuits[i].first, eval_composed_circuit.functions[i], eval_composed_circuit.num_circuit_copies[i], num_execs_components);
		}

		duplo_eval.SolderGarbledComponents(eval_composed_circuit_name, eval_composed_circuit, num_execs_components);

		std::vector<std::pair<std::string, uint32_t>> input_circuits;
		for (int c = 0; c < eval_composed_circuit.num_inp_circuits; ++c) {
			input_circuits.emplace_back(eval_composed_circuit.circuits[c]);
		}

		duplo_eval.PrepareComponents(input_circuits, num_execs_auths);

		std::vector<std::vector<uint8_t>> inputs;
		for (int i = 0; i < eval_composed_circuit.num_inp_circuits; ++i) {
			inputs.emplace_back(std::vector<uint8_t>(BITS_TO_BYTES(eval_composed_circuit.functions[i].num_eval_inp_wires)));
		}

		duplo_eval.EvalComposedComponents(eval_composed_circuit_name, inputs, eval_output_keys, num_execs_online);

		std::vector<std::pair<std::string, uint32_t>> output_circuits;
		for (int c = eval_composed_circuit.circuits.size() - eval_composed_circuit.num_out_circuits; c < eval_composed_circuit.circuits.size(); ++c) {
			output_circuits.emplace_back(eval_composed_circuit.circuits[c]);
			eval_outputs.emplace_back(std::vector<uint8_t>());
		}

		duplo_eval.DecodeKeys(output_circuits, eval_output_keys, eval_outputs, num_execs_online);
	});

	ret_const.wait();
	ret_eval.wait();
	mr_end_threading();
}
