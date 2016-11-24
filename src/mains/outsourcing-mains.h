#include "ezOptionParser/ezOptionParser.hpp"
#include "duplo/duplo-evaluator.h"
#include "duplo/duplo-constructor.h"

using namespace ez;

//Hardcoded constants
static const uint32_t network_dummy_size = 50000000;
static const uint32_t commit_dummy_size = 1000000;
static const uint32_t commit_dummy_input = 128;
static const uint32_t commit_dummy_output = 128;

//Hardcoded default values
static std::string default_num_iters("10");
static std::string default_circuit_name("outsc");
static std::string default_execs("1,1,1");
static std::string default_optimize_online("0");
static std::string default_ip_address("localhost");
static std::string default_port("28001");
static std::string default_print_format("0");

static std::string default_num_commits("10000");
static std::string default_num_commit_execs("1");

void Usage(ezOptionParser& opt) {
    std::string usage;
    opt.getUsage(usage);
    std::cout << usage;
};

void solderIdTagAesToOne(ComposedCircuit& composed_circuit,
                         Circuit& id, std::string circuit_id_name,
                         Circuit& tag, std::string circuit_tag_name,
                         Circuit& aes, std::string circuit_aes_name,
                         int num_aes_circuits) {

    composed_circuit.circuits_in_layer.resize(2);

//    Adding ID circuit to layer 0
    composed_circuit.circuits.emplace_back(std::make_pair(circuit_id_name, 0));
    composed_circuit.circuits_in_layer[0].emplace_back(0); /* Id circuit goes into layer 0 */

//    Adding TAG circuit to layer 1
    composed_circuit.circuits.emplace_back(std::make_pair(circuit_tag_name, 0));
    composed_circuit.circuits_in_layer[1].emplace_back(1); /* Tag circuit goes into layer 1 */

//    Adding AES circuit to layer 1
    composed_circuit.circuits.emplace_back(std::make_pair(circuit_aes_name, 0));
    composed_circuit.circuits_in_layer[1].emplace_back(2); /* AES circuit goes into layer 1 */

//    Updating composed circuit
    composed_circuit.num_inp_circuits = 1;
    composed_circuit.num_out_circuits = 2;

    composed_circuit.out_wire_holders.resize(composed_circuit.circuits.size());

//    Adding output holder info for TAG circuit
    std::vector<uint32_t> out_vals(id.num_out_wires);
    std::iota (std::begin(out_vals), std::end(out_vals), 0);
    composed_circuit.out_wire_holders[1].emplace_back(std::make_pair(0, out_vals));

//    Adding output holder info for AES circuit
    std::vector<uint32_t> out_vals_interval(128);
    std::iota (std::begin(out_vals_interval), std::end(out_vals_interval), 0);
    std::vector<uint32_t> out_vals_i2(128);
    std::iota (std::begin(out_vals_i2), std::end(out_vals_i2), id.num_inp_wires / 2);


    out_vals_interval.insert(std::end(out_vals_interval), std::begin(out_vals_i2), std::end(out_vals_i2));

    composed_circuit.out_wire_holders[2].emplace_back(std::make_pair(0, out_vals_interval));

//    Adding output wire pointers
    composed_circuit.out_wire_holder_to_wire_idx.emplace(0, id.num_inp_wires);
    composed_circuit.out_wire_holder_to_wire_idx.emplace(1, id.num_inp_wires + id.num_out_wires);
    composed_circuit.out_wire_holder_to_wire_idx.emplace(2, id.num_inp_wires + id.num_out_wires + tag.num_inp_wires + tag.num_out_wires);

};