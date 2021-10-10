/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

#define REGISTER_SIZE 8192
#define TIMESTAMP_WIDTH 48
#define ID_WIDTH 16
#define FLOWLET_TIMEOUT 48w200000 //200ms


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


    //TODO 5: define the id and timestamp registers
    register<bit<ID_WIDTH>>(REGISTER_SIZE)        flowlet_to_id;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flowlet_time_stamp;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action read_flowlet_registers(bit<16> num_nhops){
        //TODO 6: define the action to read the registers using the flowlet index you get from hashing the 5-tuple.
        hash(meta.flowlet_hash_index,HashAlgorithm.crc16,(bit<1>)0,{hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol},num_nhops);

        flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_hash_index);
        flowlet_time_stamp.read(meta.flowlet_timestamp, (bit<32>)meta.flowlet_hash_index);

        flowlet_time_stamp.write((bit<32>)meta.flowlet_hash_index, standard_metadata.ingress_global_timestamp);
        

    }

    action update_flowlet_id(){
       //TODO 7: define the action to update the flowlet id (if needed).
       bit<ID_WIDTH> random_number;
       random(random_number, 0, 10000);
       flowlet_to_id.write((bit<32>)meta.flowlet_hash_index,random_number);
       flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_hash_index);

    }

    //TODO 4: copy the tables and actions from ECMP
    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){

        //TODO 8: add the flowlet id to the hash function in the ecmp_group action
        hash(meta.ecmp_hash,HashAlgorithm.crc16,(bit<1>)0,{hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol, 
          meta.flowlet_id},num_nhops);

        meta.ecmp_group_id = ecmp_group_id;

    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
        bit<48> tmpAddr;
        tmpAddr = hdr.ethernet.dstAddr; 
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = tmpAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id: exact;
            meta.ecmp_hash: exact;
        }

        actions = {
            set_nhop;
            drop;
        }

        size = 1024;
        default_action = drop();


    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        
        size = 1024;
        default_action = drop();
    }

    apply {
        //TODO 9: write the ingress logic as described in the exercise description
        if (hdr.ipv4.isValid()) {
            read_flowlet_registers(4);
            if ((standard_metadata.ingress_global_timestamp - meta.flowlet_timestamp) > FLOWLET_TIMEOUT) {
                update_flowlet_id();
            }
            switch(ipv4_lpm.apply().action_run) {
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {

    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
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