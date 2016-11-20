#include "circuit.h"

#include <iostream>
#include <memory>

using namespace std;
//For Frigate
vector<Circuit> circuits;
ofstream fDuplo;

//Parse the gate description given a char array of the description file.
Circuit duploParseCircuit(char raw_circuit[]) {
	Circuit circuit;	
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //skip FN
	circuit.idxCircuit = (uint32_t) atoi(raw_circuit);
//	circuit.name_function = "FN" + to_string(circuit.idxCircuit);
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //#number num_inp_wires
	circuit.num_inp_wires = (uint32_t) atoi(raw_circuit);
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //const_inp_wires_start
	circuit.inp_wires_start = (uint32_t) atoi(raw_circuit);
	
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //#number out_inp_wires
	circuit.num_out_wires = (uint32_t) atoi(raw_circuit);	
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //const_out_wires_start
	circuit.out_wires_start = (uint32_t) atoi(raw_circuit);
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; // #number total wires
	circuit.num_wires = (uint32_t) atoi(raw_circuit);
	
	raw_circuit = strchr(raw_circuit, '\n') + 1; //Skip this line

	int curr_gate_num = 0;
	uint32_t num_inputs, left_wire_idx, right_wire_idx, out_wire_idx, num_child_func, child_wire;
	char type[4];

	while (*raw_circuit != '-') {
		if (*raw_circuit == '\n') {
			raw_circuit = strchr(raw_circuit, '\n') + 1;
			continue;
		}
		if (*raw_circuit == '+')
		{
			raw_circuit = strchr(raw_circuit, ' ') + 1; //
			raw_circuit = strchr(raw_circuit, ' ') + 1; //FN
			 num_child_func = (uint32_t) atoi(raw_circuit) - 1;
			uint32_t idx = num_child_func;
			raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
			raw_circuit = strchr(raw_circuit, ' ') + 1; //skip ++ 
			
			for (uint32_t i = 0; i < circuits[num_child_func].num_inp_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
				circuit.gates.emplace_back(Gate());
				circuit.gates[curr_gate_num].type = "XOR";
				circuit.gates[curr_gate_num].left_wire = child_wire;
				circuit.gates[curr_gate_num].right_wire = circuit.gates[1].out_wire ;
				circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].inp_wires_start + i 
														+ circuit.num_wires;
				++curr_gate_num;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}
			raw_circuit = strchr(raw_circuit, '\n') + 1;
			cout << "num_child_func " << num_child_func << endl;
			for (int j = 0; j < circuits[num_child_func].gates.size(); j++)
			{
				circuit.gates.emplace_back(Gate());
				circuit.gates[curr_gate_num].type = circuits[num_child_func].gates[j].type;
				circuit.gates[curr_gate_num].left_wire = circuits[num_child_func].gates[j].left_wire + circuit.num_wires;
				circuit.gates[curr_gate_num].right_wire = circuits[num_child_func].gates[j].right_wire + circuit.num_wires;
				circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].gates[j].out_wire + circuit.num_wires;
				++curr_gate_num;
			}
			raw_circuit = strchr(raw_circuit, ' ') + 1;
			for (int i = 0; i < circuits[num_child_func].num_out_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
				circuit.gates.emplace_back(Gate());
				circuit.gates[curr_gate_num].type = "XOR";
				circuit.gates[curr_gate_num].left_wire = child_wire;
				circuit.gates[curr_gate_num].right_wire = circuit.gates[1].out_wire;
				circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].out_wires_start + i 
														+ circuit.num_wires;
				++curr_gate_num;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}
			circuit.num_wires += circuits[num_child_func].num_wires;
		}
		else
		{
			num_inputs = (uint32_t) atoi(raw_circuit);
			raw_circuit = strchr(raw_circuit, ' ') + 1;
			raw_circuit = strchr(raw_circuit, ' ') + 1; //We skip num_output wires as they all have 1.

			if (num_inputs == 1) {
				left_wire_idx = (uint32_t) atoi(raw_circuit);
				raw_circuit = strchr(raw_circuit, ' ') + 1;
				out_wire_idx = (uint32_t) atoi(raw_circuit);
				raw_circuit = strchr(raw_circuit, ' ') + 1;
				raw_circuit = strchr(raw_circuit, '\n') + 1;
				circuit.gates.emplace_back(Gate());
				circuit.gates[curr_gate_num].type = "NOT";
				circuit.gates[curr_gate_num].left_wire = left_wire_idx;
				circuit.gates[curr_gate_num].out_wire = out_wire_idx;
				++curr_gate_num;
			}
			else {
				left_wire_idx = (uint32_t) atoi(raw_circuit);
				raw_circuit = strchr(raw_circuit, ' ') + 1;
				right_wire_idx = (uint32_t) atoi(raw_circuit);
				raw_circuit = strchr(raw_circuit, ' ') + 1;
				out_wire_idx = (uint32_t) atoi(raw_circuit);

				raw_circuit = strchr(raw_circuit, ' ') + 1;

				memcpy(type, raw_circuit, 4 * sizeof(char));
				std::string type_string(type);
				raw_circuit = strchr(raw_circuit, '\n') + 1;
				if (type_string.find("NXOR") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "NXOR";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;
					++curr_gate_num;
				}
				else if (type_string.find("XOR") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "XOR";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;
					++curr_gate_num;
				}
				else if (type_string.find("NAND") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "NAND";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;

					++curr_gate_num;
				}
				else if (type_string.find("NOR") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "NOR";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;

					++curr_gate_num;
				}
				else if (type_string.find("OR") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "OR";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;

					++curr_gate_num;
				}
				else if (type_string.find("AND") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "AND";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;

					++curr_gate_num;
				}
			}
		}
	}

	  
	return circuit;
}



void frigate_ParseComposedCircuit(char raw_circuit[]) {	
	

	uint32_t num_functions = (uint32_t) atoi(raw_circuit); //get number functions 
	circuits.resize(num_functions);

	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_layer = (uint32_t) atoi(raw_circuit); //get number functions 

	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_component = (uint32_t) atoi(raw_circuit); //get number functions 

	fDuplo << num_functions << " " << num_layer << " " << num_component << "// #numberfunction #layer  #numberComponent\n";

	raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
	uint32_t num_in_wire1 = (uint32_t) atoi(raw_circuit); //get number functions 
	
	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_in_wire2 = (uint32_t) atoi(raw_circuit); //get number functions 
	
	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_out_wire1 = (uint32_t) atoi(raw_circuit); //get number functions 

	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_out_wire2 = (uint32_t) atoi(raw_circuit); //get number functions 

	fDuplo << num_in_wire1 << " " << num_in_wire2 << " " << num_out_wire1 << " " << num_out_wire2 << " //#input_eval #input_const #output_eval #output_const\n\n";	

	raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
	raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line	

	circuits.resize(num_functions - 1);
	
	///////////////////////////
	//read each function!!!
	///////////////////////
	for (int i = 0; i < num_functions-1; i++)
	{
		circuits[i] = duploParseCircuit(raw_circuit);
		raw_circuit = strchr(raw_circuit, '-') + 1; //next function
		raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
		raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
	} //done with reading the component
	
	for (int i = 0; i < num_functions - 1; i++)
	{
		fDuplo << "FN " << circuits[i].idxCircuit << " " 
						<< circuits[i].num_inp_wires << " " 
						<< circuits[i].inp_wires_start << " " 
						<< circuits[i].num_out_wires << " " 
						<< circuits[i].out_wires_start << " " 
						<< circuits[i].num_wires << "\n";
	
		for (int j = 0; j < circuits[i].gates.size(); j++)
		{
			if (circuits[i].gates[j].type == "NOT")
				fDuplo << "1 1 ";
			else
				fDuplo << "2 1 ";
			
			fDuplo << circuits[i].gates[j].left_wire << " "
			       << circuits[i].gates[j].right_wire << " "
				   << circuits[i].gates[j].out_wire << "\n";
		}	
		fDuplo << "--end FN " << i + 1 << "--" << "\n\n";
	}
	
	

	raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line FN main
	std::string str(raw_circuit);
	fDuplo << str.substr(0,str.length()-1) << "\n" ;
}



void frigate_read_text_circuit(const char* circuit_file)
{
	FILE* file;
	size_t file_size;
	file = fopen(circuit_file, "r");

	std::string str(circuit_file);

	fDuplo.open(str + "Duplo");
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
	frigate_ParseComposedCircuit(data.get());
	fDuplo.close();
}
