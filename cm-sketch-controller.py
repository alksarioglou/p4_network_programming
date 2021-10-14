import socket, struct, pickle, os
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import *
from crc import Crc

crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]

class CMSController(object):

    def __init__(self, sw_name, set_hash):

        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.set_hash = set_hash
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)

        self.custom_calcs = self.controller.get_custom_crc_calcs()
        self.register_num =  len(self.custom_calcs)

        self.init()
        self.registers = []

    def init(self):
        if self.set_hash:
            self.set_crc_custom_hashes()
        self.create_hashes()

    def set_forwarding(self):
        self.controller.table_add("forwarding", "set_egress_port", ['1'], ['2'])
        self.controller.table_add("forwarding", "set_egress_port", ['2'], ['1'])

    def reset_registers(self):
        for i in range(self.register_num):
            self.controller.register_reset("sketch{}".format(i))

    def flow_to_bytestream(self, flow):
        return socket.inet_aton(flow[0]) + socket.inet_aton(flow[1]) + struct.pack(">HHB",flow[2], flow[3], 6)

    def set_crc_custom_hashes(self):
        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i+=1

    def create_hashes(self):
        self.hashes = []
        for i in range(self.register_num):
            self.hashes.append(Crc(32, crc32_polinomials[i], True, 0xffffffff, True, 0xffffffff))

    #Implement below
    #TODO 1: implement the read_registers(self) function
    def read_registers(self):
        for k in range(self.register_num):
            register_value = self.controller.register_read("sketch{}".format(k))
            self.registers.append(register_value)



    #TODO 2: implement the get_cms(self, flow, mod) function
    def get_cms(self, flow, mod):

        # Convert tuple to bytestream
        tuple_bytestream = self.flow_to_bytestream(flow)

        # Loop through all hash functions
        all_counts  = []
        hash_output = []

        for i in range(self.register_num):

            # Hash tuple with each hash function
            bf_mod = self.hashes[i].bit_by_bit_fast(tuple_bytestream)
            hash_output.append(bf_mod % mod)

            # Read the values in the appopriate registers
            register_count = self.registers[i][hash_output[i]]
            all_counts.append(register_count)

        # Return minimum value out of all counts
        min_value = min(all_counts)

        return min_value
        

    #TODO 3: implement the main function that decodes all the registers, and compares them to the ground truth
    def decode_registers(self, eps, n, mod, ground_truth_file="sent_flows.pickle"):

        # Define error probability desired
        delta = 0.05

        # Variable for accumulating the number of flows read at any time
        flow_no = 0

        # Variable to store the number of flows outside the error bound
        no_flows_outside = 0

        # Variables to store relative error and total error
        relative_error = 0
        total_error = 0

        # Read registers
        self.read_registers()

        # Load pickle file and create dictionaries of flows and ground truth values
        ground_truth_dict = pickle.load(open(ground_truth_file, "rb"))
        dict_flows = ground_truth_dict.keys()
        dict_real_count = ground_truth_dict.values()

        # For each flow read count value out of the registers and check if it is inside the bound
        for sp_flow,real_count in zip(dict_flows,dict_real_count):

            # Get estimate of count of the specific flow
            min_val_flow = self.get_cms(sp_flow, mod)
            #print("Starting flow {}".format(sp_flow))
            print("Estimated flow count: {} - Real count: {}".format(min_val_flow,real_count))

            # If the error exceeds the bound
            if ((min_val_flow - real_count) >= eps*n):
                no_flows_outside = no_flows_outside + 1
                print("Outside the bound!")

            # Increase number of flows read
            flow_no = flow_no + 1
            
            # Define current probability of estimations lying outside the bound
            probability = no_flows_outside/flow_no

            # Check if the L1 error bound guarantee holds
            if (probability >= delta):
                print("Error probability exceeds guarantee of δ = {} with probability of {}".format(delta,probability))

            # Calculate relative error for each flow and total error
            relative_error = min_val_flow - real_count
            #print("Relative error of the flow: {}".format(relative_error))
            total_error = total_error + relative_error

        # Print total error
        print("Total error for all flows is: {}".format(total_error))




if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', help="switch name to configure" , type=str, required=False, default="s1")
    parser.add_argument('--eps', help="epsilon to use when checking bound", type=float, required=False, default=0.01)
    parser.add_argument('--n', help="number of packets sent by the send.py app", type=int, required=False, default=1000)
    parser.add_argument('--mod', help="number of cells in each register", type=int, required=False, default=4096)
    parser.add_argument('--flow-file', help="name of the file generated by send.py", type=str, required=False, default="sent_flows.pickle")
    parser.add_argument('--option', help="controller option can be either set_hashes, decode or reset registers", type=str, required=False, default="set_hashes")
    args = parser.parse_args()

    set_hashes = args.option == "set_hashes"
    controller = CMSController(args.sw, set_hashes)

    if args.option == "decode":
        controller.decode_registers(args.eps, args.n, args.mod, args.flow_file)

    elif args.option == "reset":
        controller.reset_registers()