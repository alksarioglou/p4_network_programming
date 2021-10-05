/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_BROADCAST = 0x1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //TODO 2: define a forwarding match-action table like the one from the previous exercise. This time you can remove
    //        the broadcast action, or make it empty.
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    // Only used for packets destined to broadcast address
    // Used in basic_forwarding table
    action broadcast() {
    }

    action set_multicast_id(bit<16> multicast_id) {
        standard_metadata.mcast_grp = multicast_id;
    }


    table basic_forwarding {

        key = {
            hdr.ethernet.dstAddr: exact;
        }

        //TODO 4: Add a broadcast action to the action list and set it as default
        actions = {
            forward;
            broadcast;
            drop;
        }

        size = 8;

        default_action = broadcast();

    }

    //TODO 3: define a new match-action table that matches to the ingress_port and calls an action to set the multicast group
    table flooding {

        key = {
            standard_metadata.ingress_port: exact;
        }

        //TODO 4: Add a broadcast action to the action list and set it as default
        actions = {
            set_multicast_id;
            drop;
        }

        size = 4;

        default_action = drop();

    }   


    apply {
        //TODO 5: Build your control logic: apply the normal forwarding table,
        //        if there is a miss apply the second table to set the multicast group.
        if (!basic_forwarding.apply().hit) {
            flooding.apply();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;