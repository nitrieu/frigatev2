#include "circuit.h"

#include <iostream>
#include <memory>
#include <sstream>
#include <iostream>
#include <string.h>
#include <algorithm>
using namespace std;
//For Frigate
vector<Circuit> circuits;
ofstream fDuplo;
ofstream fBristol;
ofstream fSbox;
ofstream fFuncs;
std::string dir;
bool isAES = false;

template <typename T1, typename T2>
	struct less_second {
		typedef pair<T1, T2> type;
		bool operator ()(type const& a, type const& b) const {
			return a.second < b.second;
		}
	};

//Parse the gate description given a char array of the description file.
Circuit duploParseCircuit(char raw_circuit[]) {
	Circuit circuit;	
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //skip FN
	circuit.idxCircuit = (uint32_t) atoi(raw_circuit);
//	circuit.name_function = "FN" + to_string(circuit.idxCircuit);

	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //#number num_inp_wires
	circuit.num_inp_wires = (uint32_t) atoi(raw_circuit);	
	circuit.inp_wires_start = 0;	
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; //#number out_inp_wires
	circuit.num_out_wires = (uint32_t) atoi(raw_circuit);	
	circuit.out_wires_start = circuit.num_inp_wires;	
	
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; // #number total wires
	circuit.num_wires = (uint32_t) atoi(raw_circuit);
	
	raw_circuit = strchr(raw_circuit, ' ') + 1; // #name
	char type[4];
	memcpy(type, raw_circuit, 4 * sizeof(char));
	std::string type_string(type);
	circuit.circuit_name = type_string;
	
	raw_circuit = strchr(raw_circuit, '\n') + 1; //Skip this line

	int curr_gate_num = 0;
	uint32_t num_inputs = 0, left_wire_idx, right_wire_idx, out_wire_idx, num_child_func = 0, child_wire, num_shift = 0;
	


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
			std::unordered_map<uint32_t, uint32_t > global_inp_out_wires;
			raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
			if (*raw_circuit != '+')
			{
				fDuplo << "Error!\n";
				fDuplo << "Input Function: " << circuit.idxCircuit << "\n";
				fDuplo << "Syntax: " <<  "call function " << circuits[num_child_func].idxCircuit << " in  function " << circuit.idxCircuit;
				fDuplo.close();
				exit(1);
			}
			raw_circuit = strchr(raw_circuit, ' ') + 1; //skip ++ 

			circuit.num_non_free_gates += circuits[num_child_func].num_non_free_gates;
			
			for (uint32_t i = 0; i < circuits[num_child_func].num_inp_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
				global_inp_out_wires.emplace(i, child_wire);
//				circuit.gates.emplace_back(Gate());
//				circuit.gates[curr_gate_num].type = "XOR";
//				circuit.gates[curr_gate_num].left_wire = child_wire;
//				circuit.gates[curr_gate_num].right_wire = circuit.gates[1].out_wire;
//				circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].inp_wires_start + i 
//														+ circuit.num_wires;
//				++curr_gate_num;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}
			raw_circuit = strchr(raw_circuit, '\n') + 1;
			//cout << "num_child_func " << num_child_func << endl;


			if (*raw_circuit != '+')
			{
				fDuplo << "Error!\n";
				fDuplo << "Output Function: " << circuit.idxCircuit << "\n";
				fDuplo << "Syntax: " <<  "call function " << circuits[num_child_func].idxCircuit << " in  function " << circuit.idxCircuit;
				fDuplo.close();
				exit(1);
			}
			raw_circuit = strchr(raw_circuit, ' ') + 1;
			for (int i = 0; i < circuits[num_child_func].num_out_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
				global_inp_out_wires.emplace(i + circuits[num_child_func].num_inp_wires, child_wire);
//				circuit.gates.emplace_back(Gate());
//				circuit.gates[curr_gate_num].type = "XOR";
//				circuit.gates[curr_gate_num].left_wire = circuits[num_child_func].out_wires_start + i 
//														+ circuit.num_wires;
//				circuit.gates[curr_gate_num].right_wire = circuit.gates[1].out_wire;
//				circuit.gates[curr_gate_num].out_wire = child_wire;
//				++curr_gate_num;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}



			int num_inp_out_wires = circuits[num_child_func].num_inp_wires + circuits[num_child_func].num_out_wires;
			for (int j =0; j < circuits[num_child_func].gates.size(); j++) //skip zero/onegate =>j=2
			{
				circuit.gates.emplace_back(Gate());
				circuit.gates[curr_gate_num].type = circuits[num_child_func].gates[j].type;
				
				//left_wire
				if (circuits[num_child_func].gates[j].left_wire < num_inp_out_wires)
					circuit.gates[curr_gate_num].left_wire = global_inp_out_wires[circuits[num_child_func].gates[j].left_wire];
				//else if (circuits[num_child_func].gates[j].left_wire == circuits[num_child_func].gates[0].out_wire) //local zero gate
				//	circuit.gates[curr_gate_num].left_wire = circuit.gates[0].out_wire; //use global zero gate
			//	else if (circuits[num_child_func].gates[j].left_wire == circuits[num_child_func].gates[1].out_wire) //local one gate
			//		circuit.gates[curr_gate_num].left_wire = circuit.gates[1].out_wire;//use global one gate
				else
					circuit.gates[curr_gate_num].left_wire = circuits[num_child_func].gates[j].left_wire + circuit.num_wires;

					//right_wire
				if (circuits[num_child_func].gates[j].right_wire < num_inp_out_wires)
					circuit.gates[curr_gate_num].right_wire = global_inp_out_wires[circuits[num_child_func].gates[j].right_wire];
//				else if (circuits[num_child_func].gates[j].right_wire == num_inp_out_wires) //local zero gate
//					circuit.gates[curr_gate_num].right_wire = circuit.gates[0].out_wire; //use global zero gate
	//			else if (circuits[num_child_func].gates[j].right_wire == num_inp_out_wires+1) //local one gate
		//			circuit.gates[curr_gate_num].right_wire = circuit.gates[1].out_wire;//use global one gate
				else
					circuit.gates[curr_gate_num].right_wire = circuits[num_child_func].gates[j].right_wire + circuit.num_wires;
				
				if (circuits[num_child_func].gates[j].out_wire < num_inp_out_wires)
					circuit.gates[curr_gate_num].out_wire = global_inp_out_wires[circuits[num_child_func].gates[j].out_wire];
//				else if (circuits[num_child_func].gates[j].out_wire == num_inp_out_wires) //local zero gate
//					circuit.gates[curr_gate_num].out_wire = circuit.gates[0].out_wire; //use global zero gate
//				else if (circuits[num_child_func].gates[j].out_wire == num_inp_out_wires+1) //local one gate
//					circuit.gates[curr_gate_num].out_wire = circuit.gates[1].out_wire;//use global one gate
				else
					circuit.gates[curr_gate_num].out_wire = circuits[num_child_func].gates[j].out_wire + circuit.num_wires;

				++curr_gate_num;
			}
			
			if (circuits[num_child_func].num_wires > num_shift)
				num_shift = circuits[num_child_func].num_wires;
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
					++circuit.num_non_free_gates;
					++curr_gate_num;
				}
				else if (type_string.find("NOR") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "NOR";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;
					++circuit.num_non_free_gates;
					++curr_gate_num;
				}
				else if (type_string.find("OR") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "OR";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;
					++circuit.num_non_free_gates;
					++curr_gate_num;
				}
				else if (type_string.find("AND") != std::string::npos) {
					circuit.gates.emplace_back(Gate());
					circuit.gates[curr_gate_num].type = "AND";
					circuit.gates[curr_gate_num].left_wire = left_wire_idx;
					circuit.gates[curr_gate_num].right_wire = right_wire_idx;
					circuit.gates[curr_gate_num].out_wire = out_wire_idx;
					++circuit.num_non_free_gates;
					++curr_gate_num;
				}
				else if (type_string.find("Erro") != std::string::npos) {
					raw_circuit = strchr(raw_circuit, ' ') + 1;
					uint32_t type_gate = (uint32_t) atoi(raw_circuit);
					if (type_gate == 4) //x&!y
					{
						circuit.gates.emplace_back(Gate());
						circuit.gates[curr_gate_num].type = "NOT";
						circuit.gates[curr_gate_num].left_wire = right_wire_idx;
						circuit.gates[curr_gate_num].out_wire = circuit.num_wires + 1;
						++curr_gate_num;
						

						circuit.gates.emplace_back(Gate());
						circuit.gates[curr_gate_num].type = "AND";
						circuit.gates[curr_gate_num].left_wire = left_wire_idx;
						circuit.gates[curr_gate_num].right_wire = circuit.num_wires + 1;
						circuit.gates[curr_gate_num].out_wire = out_wire_idx;
						++curr_gate_num;
						++circuit.num_wires;
						++circuit.num_non_free_gates;
					}
				}
				raw_circuit = strchr(raw_circuit, '\n') + 1;
			}
		}
	}

	circuit.num_wires += num_shift;
	  
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
	for (int i = 0; i < num_functions - 1; i++)
	{
		circuits[i] = duploParseCircuit(raw_circuit);
	
		if (isAES && i == 0)	
			circuits[0] = read_text_sBoxYale();

		raw_circuit = strchr(raw_circuit, '-') + 1; //next function
		raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
		raw_circuit = strchr(raw_circuit, '\n') + 1; //skip line
	} //done with reading the component
	
	

//////////
///DUPLO format
/////////	
	
	string strFunction[num_functions - 1];

//	fDuplo << num_functions << " " << num_layer << " " << num_component << "\n";//" // #numberfunction #layer  #numberComponent\n";
//	fDuplo << num_const_inp_wires << " " << num_eval_inp_wires << " " << num_const_out_wires << " " << num_eval_out_wires << "\n";//" //#input_eval #input_const #output_eval #output_const\n\n";	
	for (int i = 0; i < num_functions - 1; i++)
	{	

		//fDuplo << "FN " << circuits[i].idxCircuit << " " 
//						<< circuits[i].num_inp_wires << " " 
//						<< circuits[i].num_out_wires << " " 
//						<< circuits[i].num_wires << "\n";//<< "//# FN id num_inp_wires num_out_wires num_wires //"  << "non-free-gate: " << circuits[i].num_non_free_gates << "\n";

		for (int j = 0; j < circuits[i].gates.size(); j++)
		{
			if (circuits[i].gates[j].type == "NOT")
			{
				strFunction[i].append("1 1 " 
				 + to_string(circuits[i].gates[j].left_wire) + " "
					 + to_string(circuits[i].gates[j].out_wire) + " "
					 + circuits[i].gates[j].type + "\n");
			}
			else
			{
				strFunction[i].append("2 1 "
						+ to_string(circuits[i].gates[j].left_wire) + " "
						  + to_string(circuits[i].gates[j].right_wire) + " "
						   + to_string(circuits[i].gates[j].out_wire) + " "
					+ circuits[i].gates[j].type + "\n");
			}
			
		}	
		//fDuplo << strFunction[i];
		//fDuplo << "--end FN " << circuits[i].idxCircuit  << " -- \n\n";

//	ofstream fFuncs1;
//	fFuncs1.open(dir + "_duplo_function_test"+to_string(i));
//		fFuncs1 << circuits[i].circuit_name << endl;
//	fFuncs1 << circuits[i].num_non_free_gates << endl;
//	fFuncs1 << strFunction[i];
//	fFuncs1.close();
	}


	raw_circuit = strchr(raw_circuit, '\n') + 1;
	//raw_circuit = strchr(raw_circuit, '\n') + 1;
	std::istringstream type_string(raw_circuit);
	string line;
//	while (getline(type_string, line) && !type_string.eof()) {
//		fDuplo << line << "\n";
//	}

//	raw_circuit = strchr(raw_circuit, '\n') + 1;
	int pos;
	vector <std::tuple<int, string, string>> functions_duplo;
	std::map<uint32_t, uint32_t> real_functions;
	int num_function;
	string input_func, output_func;
	int idx_func=1;

	while (getline(type_string, line) && !type_string.eof()) {
		
		if (!line.empty() && line.at(0) == 'F') //FN 2
		{
			pos = line.find("\n"); //out_wire
			line.erase(0, 3); // 'FN '
			num_function = std::stoi(line.substr(0, pos)); //2		
			
			getline(type_string, input_func);
			getline(type_string, output_func);	

			if (real_functions.find(num_function) == real_functions.end()) {
				real_functions.emplace(num_function, idx_func);
				idx_func++;
			}
			functions_duplo.push_back(std::make_tuple(real_functions[num_function], input_func, output_func));	
	
		}
	}

	
	fDuplo << real_functions.size() << " " << functions_duplo.size() << " " << functions_duplo.size() << "\n";//" // #numberfunction #layer  #numberComponent\n";
	fDuplo << num_const_inp_wires << " " << num_eval_inp_wires << " " << num_const_out_wires << " " << num_const_out_wires << " " << num_eval_out_wires << "\n\n";// " //#input_eval #input_const #output_eval #output_const\n\n";
	

	int id = 1;

	//sort by value
	vector<pair<uint32_t, uint32_t> > mapcopy(real_functions.begin(), real_functions.end());
	sort(mapcopy.begin(), mapcopy.end(), less_second<uint32_t, uint32_t>());

	
	for (auto it = mapcopy.begin(); it != mapcopy.end(); ++it)
	{
		
		//std::cout << " " << it->first << ":" << it->second;
		string head_func;

		head_func.append("FN " + to_string(it->second)  + " "  
					+ to_string(circuits[it->first - 1].num_inp_wires) + " " 
					+ to_string(circuits[it->first - 1].num_out_wires) + " " 
					+ to_string(circuits[it->first - 1].num_wires) + "\n"); //# FN id num_inp_wires num_out_wires num_wires \n";
		
		fDuplo << head_func;
		fDuplo << strFunction[it->first - 1];
		fDuplo << "--end FN " << it->second << " -- \n\n";

		auto aa = to_string(it->second);		
		fFuncs.open(dir + "_duplo_function_" + to_string(it->second));
		//fFuncs << circuits[it->first - 1].circuit_name << " " << circuits[it->first - 1].num_non_free_gates <<  endl;
		fFuncs << head_func;
		fFuncs << strFunction[it->first - 1];
		fFuncs.close();

		id++;
	}

	fDuplo << "FN " << real_functions.size() + 1 << "\n\n"; 
	
	for (int i = 0; i <  functions_duplo.size(); i++)
	{
		fDuplo << "FN " << std::get<0>(functions_duplo[i]) << "\n";
		fDuplo << std::get<1>(functions_duplo[i]) << "\n";
		fDuplo << std::get<2>(functions_duplo[i]) << "\n\n";
	}


//////////
///Bristol format
/////////	

	Circuit main_circuit;
	raw_circuit = strchr(raw_circuit, '\n') + 1; //FN main
	vector <std::pair<int, std::unordered_map<int, int>>> functions;

	uint32_t num_child_func = 0, child_wire, curr_gate_num, one_gate, zero_gate, num_shift = 0, num_non_free_gates = 0, max_wire = 0;
	curr_gate_num = 0;

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
			//cout << num_child_func << "\n";
			std::unordered_map<int,int> global_inp_out_wires;
			for (uint32_t i = 0; i < circuits[num_child_func].num_inp_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
			//	cout << child_wire << " ";
				global_inp_out_wires.emplace(i, child_wire);
				if (child_wire > max_wire)
					max_wire = child_wire;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}
		//	cout << "\n ";
			for (int i = 0; i < circuits[num_child_func].num_out_wires; i++)
			{
				child_wire = (uint32_t) atoi(raw_circuit);
				//cout << child_wire << " ";
				global_inp_out_wires.emplace(i + circuits[num_child_func].num_inp_wires, child_wire);
				if (child_wire > max_wire)
					max_wire = child_wire;
				raw_circuit = strchr(raw_circuit, ' ') + 1;
			}
			//cout << "\n ";
			functions.push_back(std::make_pair(num_child_func, global_inp_out_wires));
		}
	}

	main_circuit.num_wires = max_wire + 1;

//	one_gate = main_circuit.num_wires;
//	zero_gate = one_gate + 1;
//	main_circuit.num_wires += 2;
//
//	//add zero, one gate
//	main_circuit.gates.emplace_back(Gate());
//	main_circuit.gates[curr_gate_num].type = "NXOR";
//	main_circuit.gates[curr_gate_num].left_wire = 0;
//	main_circuit.gates[curr_gate_num].right_wire = 0;
//	main_circuit.gates[curr_gate_num].out_wire = one_gate;
//	++curr_gate_num;
//
//
//	main_circuit.gates.emplace_back(Gate());
//	main_circuit.gates[curr_gate_num].type = "XOR";
//	main_circuit.gates[curr_gate_num].left_wire = 0;
//	main_circuit.gates[curr_gate_num].right_wire = 0;
//	main_circuit.gates[curr_gate_num].out_wire = zero_gate;
//	++curr_gate_num;

	for (int i = 0; i < functions.size(); i++)
	{		
		
//		for (uint32_t j = 0; j < circuits[std::get<0>(functions[i])].num_inp_wires; j++)
//		{
//			main_circuit.gates.emplace_back(Gate());
//			main_circuit.gates[curr_gate_num].type = "XOR";
//			main_circuit.gates[curr_gate_num].left_wire = std::get<1>(functions[i])[j];
//			main_circuit.gates[curr_gate_num].right_wire = 	zero_gate;
//			main_circuit.gates[curr_gate_num].out_wire = circuits[std::get<0>(functions[i])].inp_wires_start + j + main_circuit.num_wires;
//			++curr_gate_num;
//		}

		int num_inp_out_wires = circuits[std::get<0>(functions[i])].num_inp_wires + circuits[std::get<0>(functions[i])].num_out_wires;
		for (int j = 0; j < circuits[std::get<0>(functions[i])].gates.size(); j++)
		{
			main_circuit.gates.emplace_back(Gate());

			if (circuits[std::get<0>(functions[i])].gates[j].type == "AND" || 
				circuits[std::get<0>(functions[i])].gates[j].type == "NAND" ||
				circuits[std::get<0>(functions[i])].gates[j].type == "OR" ||
				circuits[std::get<0>(functions[i])].gates[j].type == "NOR")
			{
				num_non_free_gates++;
			}
				
			main_circuit.gates[curr_gate_num].type = circuits[std::get<0>(functions[i])].gates[j].type;
			//left_wire
			if (circuits[std::get<0>(functions[i])].gates[j].left_wire < num_inp_out_wires)
				main_circuit.gates[curr_gate_num].left_wire = std::get<1>(functions[i])[circuits[std::get<0>(functions[i])].gates[j].left_wire];
			else
				main_circuit.gates[curr_gate_num].left_wire = circuits[std::get<0>(functions[i])].gates[j].left_wire + main_circuit.num_wires;
			
			//right_wire
			if (circuits[std::get<0>(functions[i])].gates[j].right_wire < num_inp_out_wires)
				main_circuit.gates[curr_gate_num].right_wire = std::get<1>(functions[i])[circuits[std::get<0>(functions[i])].gates[j].right_wire];
			else
				main_circuit.gates[curr_gate_num].right_wire = circuits[std::get<0>(functions[i])].gates[j].right_wire + main_circuit.num_wires;

			if (circuits[std::get<0>(functions[i])].gates[j].out_wire < num_inp_out_wires)
				main_circuit.gates[curr_gate_num].out_wire = std::get<1>(functions[i])[circuits[std::get<0>(functions[i])].gates[j].out_wire];
			else
				main_circuit.gates[curr_gate_num].out_wire = circuits[std::get<0>(functions[i])].gates[j].out_wire + main_circuit.num_wires;
			++curr_gate_num;
		}
//		for (int j = 0; j < circuits[std::get<0>(functions[i])].num_out_wires; j++)
//		{
//			main_circuit.gates.emplace_back(Gate());
//			main_circuit.gates[curr_gate_num].type = "XOR";
//			main_circuit.gates[curr_gate_num].left_wire = circuits[std::get<0>(functions[i])].out_wires_start + j 
//													+ main_circuit.num_wires; 
//			main_circuit.gates[curr_gate_num].right_wire = zero_gate;
//			main_circuit.gates[curr_gate_num].out_wire =  std::get<2>(functions[i])[j]; 
//			++curr_gate_num;
//		}
				if (circuits[std::get<0>(functions[i])].num_wires > num_shift)
					num_shift = circuits[std::get<0>(functions[i])].num_wires;

		//main_circuit.num_wires = main_circuit.num_wires + circuits[std::get<0>(functions[i])].num_wires;
	}
	main_circuit.num_wires = main_circuit.num_wires + num_shift;
	fBristol << main_circuit.gates.size() << " " << main_circuit.num_wires << " " 
										  << num_eval_inp_wires + num_const_inp_wires
										  << " //#gates, #wires, #out_wires_start // " 
										  << "# num_non_free_gates  = "  << num_non_free_gates << " " << " \n"; //#gate #wires
	fBristol << num_const_inp_wires << " " << num_eval_inp_wires 
									<< " " << num_const_out_wires 
									<< " " << num_const_out_wires  
									 << " " << num_eval_out_wires 
									 << "  //#const_inputs #eval_inputs #total_outputs* #const_outputs #eval_outputs\n\n";	 //#input_eval #input_const #output_eval


	
	for (int j = 0; j < main_circuit.gates.size(); j++)
	{
		if (main_circuit.gates[j].type == "NOT")
		{
			fBristol << "1 1 "
			<< main_circuit.gates[j].left_wire << " "
					   << main_circuit.gates[j].out_wire << " "
			<< main_circuit.gates[j].type << "\n";
		}
		else
		{
			fBristol << "2 1 "
					<< main_circuit.gates[j].left_wire << " "
					   << main_circuit.gates[j].right_wire << " "
					   << main_circuit.gates[j].out_wire << " "
			<< main_circuit.gates[j].type << "\n";
		}
			
	}
}


void frigate_read_text_circuit(const char* circuit_file)
{
	FILE* file;
	size_t file_size;
	file = fopen(circuit_file, "r");

	std::string str(circuit_file);
	dir = str;
	if (strstr(str.c_str(), "aes"))
		isAES = true;

	fDuplo.open(str + "_duplo");
	fBristol.open(str + "_bristol");
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
	fBristol.close();
}

void print_wires(std::unordered_map<string, uint32_t> wires)
{
	for (const auto& i : wires) {
		std::cout << "Key:[" << i.first << "] Value:[" << i.second << "]\n";
	}
}
//Sbox
Circuit sBoxYale_parse(char raw_circuit[]) { 
	Circuit sBox;
	std::unordered_map<string, uint32_t> wires;
	string line, left_wire, right_wire, out_wire, gate;
	int pos, pos_wire, curr_wire_num = 0, curr_gate_num = 0;
	std::string delimiter = "\n";

	sBox.num_inp_wires = 8;
	sBox.num_out_wires = 8;
	sBox.inp_wires_start = 0;
	sBox.out_wires_start = 8;

	for (int i = 0; i < sBox.num_inp_wires; i++)
	{
		wires.emplace("x" + to_string(i), 7-i); //input wires
		wires.emplace("s" + to_string(i), 7-i + 8); //output wires
		curr_wire_num += 2;
	}

	//print_wires(wires);
	
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
	int cnt_gate = 0;
	while (curr_gate_num != 115 && !type_string.eof() && getline(type_string, line)) {
		if (!line.empty() && line.at(0) == ' ')
		{
			//cout << "\n" << line << "\n";//y14 = x3 + x5;
			//line.erase(0,  2); // remove " " at the first line
			line.erase(0, line.find_first_not_of(' '));  
			if (line.at(0) != '/')
			{
				pos_wire = line.find(" "); //out_wire
				out_wire = line.substr(0, pos_wire); //y14
				//cout << out_wire << " ";
				if (wires.find(out_wire) == wires.end()) //check whether wires exits
				{
					wires.emplace(out_wire, curr_wire_num); //sBox.num_wires start from 1
					++curr_wire_num;
				}
			
				line.erase(0, pos_wire + 3); // ' = '
			
				pos_wire = line.find(" "); //right_wire
				right_wire = line.substr(0, pos_wire); //x3
				//cout << right_wire << " ";

				if (wires.find(right_wire) == wires.end()) //check whether wires exits
				{
					wires.emplace(right_wire, curr_wire_num); //sBox.num_wires start from 1
					++curr_wire_num;
				}
				line.erase(0, pos_wire + 1);

				pos_wire = line.find(" "); //gate
				gate = line.substr(0, pos_wire); //+
				//cout << gate << " ";

				if (gate == "+") 
					gate = "XOR";
				else if (gate == "X")
				{
					gate = "AND";
					sBox.num_non_free_gates++;
				}
				else if (gate == "XNOR")
					gate = "NXOR";
				else
					exit(1);

				line.erase(0, pos_wire + 1);

				pos_wire = line.find(";"); //left_wire
				left_wire = line.substr(0, pos_wire); //x5
				//cout << left_wire << " ";

				if (wires.find(left_wire) == wires.end()) //check whether wires exits
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
	}
	sBox.num_wires = curr_wire_num;
	
	fSbox << "FN " <<  sBox.gates.size() << " " << sBox.num_wires << " //#gate #wires \n";
	for (int i = 0; i < sBox.gates.size(); i++)
	{
		fSbox << "2 1 " << sBox.gates[i].left_wire  << " " << sBox.gates[i].right_wire  << " "
						 << sBox.gates[i].out_wire << " " << sBox.gates[i].type << "\n"; 
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
