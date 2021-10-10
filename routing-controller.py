from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import numpy as np

class RoutingController(object):

    def __init__(self):

        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def set_table_defaults(self):
        for controller in self.controllers.values():
            controller.table_set_default("ipv4_lpm", "drop", [])
            controller.table_set_default("ecmp_group_to_nhop", "drop", [])

    def route(self):
        """implement this function"""
        get_switches_names = self.topo.get_p4switches()
        switches_list = list(get_switches_names.keys())

        prefix = "/32"

        # Create arrays to save number of shortest paths and next hops
        shortest_path_num      = np.zeros((len(switches_list),len(switches_list)),dtype=int)
        shortest_path_next_hop = []

        # Compute shortest paths
        for i in switches_list:
            src_next_hops = []
            for j in switches_list:
                dst_next_hops = []
                src_ind = switches_list.index(i)
                dst_ind = switches_list.index(j)
                shortest_path = self.topo.get_shortest_paths_between_nodes(str(i),str(j))
                for k in range(len(shortest_path)):
                    if (len(shortest_path[k]) > 1):
                        dst_next_hops.append(shortest_path[k][1])
                    else:
                        dst_next_hops.append(shortest_path[k][0])
                src_next_hops.append(dst_next_hops)
                shortest_path_num[src_ind][dst_ind] = len(shortest_path)
            shortest_path_next_hop.append(src_next_hops)
        
        # Populate tables
        src_sw=0
        ecmp_group_id = 0
        max_group_id = 0

        # Iterate over different source switches
        for controller in self.controllers.values():

            # Array used for next hops
            next_hops_save = []

            direct_hosts = self.topo.get_hosts_connected_to(str(switches_list[src_sw]))
            #print(direct_hosts)

            for host in direct_hosts:
                host_ip = self.topo.get_host_ip(host) + prefix
                host_mac = self.topo.get_host_mac(host)
                interf_info = self.topo.get_node_intfs(fields=['node_neigh','port'])
                interf_info_sw = interf_info[str(switches_list[src_sw])]
                for i in interf_info_sw:
                    if (interf_info_sw[i][0] == host):
                        host_port = interf_info_sw[i][1]
                        break
                # Add table entries for directly connected hosts
                controller.table_add("ipv4_lpm", "set_nhop", [str(host_ip)], [host_mac, str(host_port)])

            for dst_sw in range(len(switches_list)):

                # If src and dst switches are the same
                if (src_sw == dst_sw):
                    continue

                # If src and dst switches are different
                else:

                    # If single shortest path
                    if (shortest_path_num[src_sw][dst_sw] == 1):

                        # Find next hop port
                        next_hop = shortest_path_next_hop[src_sw][dst_sw][0]
                        interf_info = self.topo.get_node_intfs(fields=['node_neigh','port'])
                        interf_info_sw = interf_info[str(switches_list[src_sw])]
                        for i in interf_info_sw:
                            if (interf_info_sw[i][0] == next_hop):
                                next_hop_port = interf_info_sw[i][1]
                                break
                        # Find ip and mac addr of dst host
                        dst_dct_hosts = self.topo.get_hosts_connected_to(str(switches_list[dst_sw]))
                        for host in dst_dct_hosts:
                            host_ip = self.topo.get_host_ip(host) + prefix
                            host_mac = self.topo.get_host_mac(host)
                            # Add table entries for directly connected hosts
                            controller.table_add("ipv4_lpm", "set_nhop", [str(host_ip)], [host_mac, str(next_hop_port)])

                    # If multiple shortest paths
                    else:

                        # Find number of next hops
                        no_next_hops = shortest_path_num[src_sw][dst_sw]

                        # Save next hops for comparison later
                        if (len(next_hops_save) == 0):
                            first_next_hops = []
                            for nhop in range(no_next_hops):
                                first_next_hops.append(shortest_path_next_hop[src_sw][dst_sw][nhop])
                            next_hops_save.append(first_next_hops)
                        
                        # Compare next hops
                        else:
                            exists = False
                            current_next_hops_save = []
                            # Load current next hops
                            for nhop in range(shortest_path_num[src_sw][dst_sw]):
                                current_next_hops_save.append(shortest_path_next_hop[src_sw][dst_sw][nhop])
                            # Compare with the existing ecmp_group_ids
                            for group in range(len(next_hops_save)):
                                if (set(next_hops_save[group]) == set(current_next_hops_save)):
                                    ecmp_group_id = group
                                    exists = True
                                    break
                                else:
                                    continue

                            # Create new ecmp_group_id
                            if (exists == False):
                                max_group_id = max_group_id + 1
                                ecmp_group_id = max_group_id
                                next_hops_save.append(current_next_hops_save)

                        # Find ip addr of dst host
                        dst_dct_hosts = self.topo.get_hosts_connected_to(str(switches_list[dst_sw]))
                        for host in dst_dct_hosts:
                            host_ip = self.topo.get_host_ip(host) + prefix
                            # Add table entries for directly connected hosts
                            controller.table_add("ipv4_lpm", "ecmp_group", [str(host_ip)], [str(ecmp_group_id), str(no_next_hops)])
                        
                        # Add entries in the table ecmp_group_to_nhop for every next hop
                        # Get mac addr and port for next hops
                        for i in range(no_next_hops):
                            next_hop = shortest_path_next_hop[src_sw][dst_sw][i]
                            dst_dct_hosts = self.topo.get_hosts_connected_to(str(switches_list[dst_sw]))
                            for host in dst_dct_hosts:
                                host_mac = self.topo.get_host_mac(host)
                                interf_info = self.topo.get_node_intfs(fields=['node_neigh','port'])
                                interf_info_sw = interf_info[str(switches_list[src_sw])]
                                for m in interf_info_sw:
                                    if (interf_info_sw[m][0] == next_hop):
                                        next_hop_port = interf_info_sw[m][1]
                                        break
                                # Add new ecmp_group in the table
                                controller.table_add("ecmp_group_to_nhop", "set_nhop", [str(ecmp_group_id), str(i)], [host_mac, str(next_hop_port)])

            print("Done with source switch: {}".format(src_sw+1))
            print()
            print()
            src_sw = src_sw + 1



    def main(self):
        self.route()


if __name__ == "__main__":
    controller = RoutingController().main()
