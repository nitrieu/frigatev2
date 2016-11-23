#include "circuit.h"

#include <iostream>
#include <memory>
#include <sstream>
#include <iostream>
using namespace std;
//For Frigate
vector<Circuit> circuits;
ofstream fDuplo;
ofstream fSbox;
bool isAES=false;

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
				else if (type_string.find("Erro") != std::string::npos) {
					raw_circuit = strchr(raw_circuit, ' ') + 1;
					uint32_t type_gate= (uint32_t) atoi(raw_circuit);
					if (type_gate == 4) //x&!y
					{
						circuit.gates.emplace_back(Gate());
						circuit.gates[curr_gate_num].type = "NOT";
						circuit.gates[curr_gate_num].left_wire = right_wire_idx;
						circuit.gates[curr_gate_num].out_wire = circuit.num_wires+1;
						++curr_gate_num;
						

						circuit.gates.emplace_back(Gate());
						circuit.gates[curr_gate_num].type = "AND";
						circuit.gates[curr_gate_num].left_wire = left_wire_idx;
						circuit.gates[curr_gate_num].right_wire = circuit.num_wires + 1;
						circuit.gates[curr_gate_num].out_wire = out_wire_idx;
						++curr_gate_num;
						++circuit.num_wires;
				
					}}
				raw_circuit = strchr(raw_circuit, '\n') + 1;
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

	
	raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
	uint32_t num_const_inp_wires = (uint32_t) atoi(raw_circuit); //get number functions 
	
	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_eval_inp_wires = (uint32_t) atoi(raw_circuit); //get number functions 
	
	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_const_out_wires = (uint32_t) atoi(raw_circuit); //get number functions 

	raw_circuit = strchr(raw_circuit, ' ') + 1;
	uint32_t num_eval_out_wires = (uint32_t) atoi(raw_circuit); //get number functions 


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
	

#if 1 //if duplo => print component
	
	//if (isAES)	
	//	circuits[1] = read_text_sBoxYale;
	
	fDuplo << num_functions << " " << num_layer << " " << num_component << "// #numberfunction #layer  #numberComponent\n";
	fDuplo << num_const_inp_wires << " " << num_eval_inp_wires << " " << num_const_out_wires << " " << num_eval_out_wires << " //#input_eval #input_const #output_eval #output_const\n\n";	
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
			{
				fDuplo << "1 1 "
				<< circuits[i].gates[j].left_wire << " "
						   << circuits[i].gates[j].out_wire << " "
					<< circuits[i].gates[j].type << "\n";
			}
			else
			{
				fDuplo << "2 1 "
						<< circuits[i].gates[j].left_wire << " "
						   << circuits[i].gates[j].right_wire << " "
						   << circuits[i].gates[j].out_wire << " "
					<< circuits[i].gates[j].type << "\n";
			}
			
		}	
		fDuplo << "--end FN " << i + 1 << "--" << "\n\n";
	}
	raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line FN main
	std::string str(raw_circuit);
	fDuplo << str.substr(0,str.length()-1) << "\n" ;
#else
	Circuit main_circuit;
	raw_circuit = strchr(raw_circuit, '\n') + 1; //FN main

	uint32_t num_child_func, child_wire, curr_gate_num, one_gate, zero_gate, num_shift;
	curr_gate_num = 0;
	one_gate = num_const_inp_wires + num_eval_inp_wires + num_const_out_wires + num_eval_out_wires;
	zero_gate = one_gate + 1;
	main_circuit.num_wires = zero_gate + 1;

	//add zero, one gate
	main_circuit.gates.emplace_back(Gate());
	main_circuit.gates[curr_gate_num].type = "NXOR";
	main_circuit.gates[curr_gate_num].left_wire = 0;
	main_circuit.gates[curr_gate_num].right_wire = 0;
	main_circuit.gates[curr_gate_num].out_wire = one_gate;
	++curr_gate_num;


	main_circuit.gates.emplace_back(Gate());
	main_circuit.gates[curr_gate_num].type = "XOR";
	main_circuit.gates[curr_gate_num].left_wire = 0;
	main_circuit.gates[curr_gate_num].right_wire = 0;
	main_circuit.gates[curr_gate_num].out_wire = zero_gate;
	++curr_gate_num;

	while (*raw_circuit != EOF) {
		if (*raw_circuit == '\n') {
			raw_circuit = strchr(raw_circuit, '\n') + 1;
			continue;
		}

		if (*raw_circuit == 'F')
		{
			raw_circuit = strchr(raw_circuit, ' ') + 1; //
			num_child_func = (uint32_t) atoi(raw_circuit) - 1;
			raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
			
			for (uint32_t i = 0; i < circuits[num_child_func].num_inp_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
				main_circuit.gates.emplace_back(Gate());
				main_circuit.gates[curr_gate_num].type = "XOR";
				main_circuit.gates[curr_gate_num].left_wire = child_wire;
				main_circuit.gates[curr_gate_num].right_wire = 	zero_gate;
				main_circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].inp_wires_start + i + main_circuit.num_wires;
				++curr_gate_num;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}
			raw_circuit = strchr(raw_circuit, '\n') + 1;
		//	cout << "num_child_func " << num_child_func << endl;
			for (int j = 0; j < circuits[num_child_func].gates.size(); j++)
			{
				main_circuit.gates.emplace_back(Gate());
				main_circuit.gates[curr_gate_num].type = circuits[num_child_func].gates[j].type;
				main_circuit.gates[curr_gate_num].left_wire = circuits[num_child_func].gates[j].left_wire + main_circuit.num_wires;
				main_circuit.gates[curr_gate_num].right_wire = circuits[num_child_func].gates[j].right_wire + main_circuit.num_wires;
				main_circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].gates[j].out_wire + main_circuit.num_wires;
				++curr_gate_num;
			}
			for (int i = 0; i < circuits[num_child_func].num_out_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
				main_circuit.gates.emplace_back(Gate());
				main_circuit.gates[curr_gate_num].type = "XOR";
				main_circuit.gates[curr_gate_num].left_wire = child_wire;
				main_circuit.gates[curr_gate_num].right_wire = zero_gate;
				main_circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].out_wires_start + i 
														+ main_circuit.num_wires;
				++curr_gate_num;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}
			main_circuit.num_wires += circuits[num_child_func].num_wires;
		}
	}

	fDuplo << num_const_inp_wires << " " << num_eval_inp_wires << " " << num_const_out_wires << " "
	       << num_eval_out_wires << " " << main_circuit.num_wires <<"//#input_eval #input_const #output_eval #output_const #num_wires \n\n";	
	
		for(int j = 0 ; j < main_circuit.gates.size() ; j++)
		{
			if (main_circuit.gates[j].type == "NOT")
			{
				fDuplo << "1 1 "
				<< main_circuit.gates[j].left_wire << " "
						   << main_circuit.gates[j].out_wire << " "
					<< main_circuit.gates[j].type << "\n";
			}
			else
			{
				fDuplo << "2 1 "
						<< main_circuit.gates[j].left_wire << " "
						   << main_circuit.gates[j].right_wire << " "
						   << main_circuit.gates[j].out_wire << " "
					<< main_circuit.gates[j].type << "\n";
			}
			
		}
#endif

}


void frigate_read_text_circuit(const char* circuit_file)
{
	FILE* file;
	size_t file_size;
	file = fopen(circuit_file, "r");

	std::string str(circuit_file);

	fDuplo.open(str + "dp");
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

void print_wires(std::unordered_map<string, uint32_t> wires)
{
	for (const auto& i : wires) {
		std::cout << "Key:[" << i.first << "] Value:[" << i.second << "]\n";
	}
}
//Sbox
Circuit sBoxYale_parse(char raw_circuit[]){ 
	Circuit sBox;
	std::unordered_map<string, uint32_t> wires;
	string line, left_wire, right_wire, out_wire, gate;
	int pos, pos_wire, curr_wire_num = 0, curr_gate_num=0;
	std::string delimiter = "\n";

	sBox.num_inp_wires = 8;
	sBox.num_out_wires = 8;
	sBox.inp_wires_start = 0;
	sBox.out_wires_start = 8;

	for (int i = 0; i < sBox.num_inp_wires; i++)
	{
		wires.emplace("x"+to_string(i), i); //input wires
		wires.emplace("s"+to_string(i), i+8); //output wires
		curr_wire_num+=2;
	}

	print_wires(wires);
	
	raw_circuit = strchr(raw_circuit, '\n') + 1; // Jan 18 +  09
	raw_circuit = strchr(raw_circuit, '\n') + 1; // Straight-line program for AES sbox 
	raw_circuit = strchr(raw_circuit, '\n') + 1; // Joan Boyar and Rene Peralta
	raw_circuit = strchr(raw_circuit, '\n') + 1;
	raw_circuit = strchr(raw_circuit, '\n') + 1; // input is X0 + ..,X7  
	raw_circuit = strchr(raw_circuit, '\n') + 1; //output is S0 + ...,S7
	raw_circuit = strchr(raw_circuit, '\n') + 1;// arithmetic is over GF2
	raw_circuit = strchr(raw_circuit, '\n') + 1;
	raw_circuit = strchr(raw_circuit, '\n') + 1;// begin top linear transformation 
	
	std::istringstream type_string(raw_circuit);
	while (getline(type_string, line) && !type_string.eof()) {
		cout << "\n" << line << "\n";//y14 = x3 + x5;
		//line.erase(0,  2); // remove " " at the first line
		line.erase(0, line.find_first_not_of(' '));  
		if (line.at(0) != '/')
		{
			pos_wire = line.find(" "); //out_wire
			out_wire = line.substr(0, pos_wire); //y14
			cout << out_wire << " ";
			if (wires.find(out_wire) == wires.end()) //check whether wires exits
			{
				wires.emplace(out_wire, curr_wire_num); //sBox.num_wires start from 1
				++curr_wire_num;
			}
			
			line.erase(0, pos_wire + 3); // ' = '
			
			pos_wire = line.find(" "); //right_wire
			right_wire = line.substr(0, pos_wire); //x3
			cout << right_wire << " ";

			if (wires.find(right_wire) == wires.end()) //check whether wires exits
			{
				wires.emplace(right_wire, curr_wire_num); //sBox.num_wires start from 1
				++curr_wire_num;
			}
			line.erase(0, pos_wire + 1);

			pos_wire = line.find(" "); //gate
			gate = line.substr(0, pos_wire); //+
			cout << gate << " ";

			if (gate == "+") 
				gate = "XOR";
			else if (gate == "X")
				gate = "AND";
			else if (gate == "XNOR")
				gate = "XNOR";
			else
				exit(1);

			line.erase(0, pos_wire + 1);

			pos_wire = line.find(";"); //left_wire
			left_wire = line.substr(0, pos_wire); //x5
			cout << left_wire << " ";

			if (wires.find(left_wire) != wires.end()) //check whether wires exits
			{
				wires.emplace(left_wire, curr_wire_num); //sBox.num_wires start from 1
				++curr_wire_num;
			}

			sBox.gates.emplace_back(Gate());
			sBox.gates[curr_gate_num].type = gate;
			sBox.gates[curr_gate_num].left_wire =  wires[left_wire];
			sBox.gates[curr_gate_num].right_wire =  wires[right_wire];
			sBox.gates[curr_gate_num].out_wire = wires[out_wire];
			++curr_gate_num;
		}
	}	
	sBox.num_wires = curr_wire_num;
	
	fSbox << "FN " <<  sBox.gates.size() << " " << sBox.num_wires << " //#gate #wires \n";
	for (int i = 0; i < sBox.gates.size(); i++)
	{
		fSbox << "2 1 " << sBox.gates[curr_gate_num].left_wire  << " " << sBox.gates[curr_gate_num].right_wire  << " "
						 << sBox.gates[curr_gate_num].out_wire << " " << sBox.gates[curr_gate_num].type << "\n"; 
	}
	return sBox;
}

Circuit read_text_sBoxYale()
{
	FILE* file;
	size_t file_size;
	const char* circuit_file = "tests/dp/AES_SBox.txt";
	file = fopen(circuit_file, "r");

	std::string str(circuit_file);

	
	fSbox.open(str + "GC");
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
	Circuit sBox = sBoxYale_parse(data.get());
	fSbox.close();
	return sBox;
}
