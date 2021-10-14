/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 4096
#define SKETCH_CELL_BIT_WIDTH 64 //Max counter size

/* MACRO */
#define SKETCH_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch##num   


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

    //TODO 4: define N registers
    SKETCH_REGISTER(0);
    SKETCH_REGISTER(1);
    SKETCH_REGISTER(2);
    

    action drop() {
        mark_to_drop(standard_metadata);
    }

    //TODO 2: define the set_egress_port action
    action set_egress_port(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    //TODO 5: Define the sketch_count action
    action sketch_count() {

        // Hash functions
        hash(meta.hash0, 
        HashAlgorithm.crc32_custom, 
        (bit<1>)0, 
        {hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol
        },(bit<16>)SKETCH_BUCKET_LENGTH);

        hash(meta.hash1, 
        HashAlgorithm.crc32_custom, 
        (bit<1>)0, 
        {hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol
        },(bit<16>)SKETCH_BUCKET_LENGTH);

        hash(meta.hash2, 
        HashAlgorithm.crc32_custom, 
        (bit<1>)0, 
        {hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol
        },(bit<16>)SKETCH_BUCKET_LENGTH);

        // Read count values
        sketch0.read(meta.counter_reg0, meta.hash0);
        sketch1.read(meta.counter_reg1, meta.hash1);
        sketch2.read(meta.counter_reg2, meta.hash2);

        // Increase variable by 1
        meta.counter_reg0 = meta.counter_reg0 + 1;
        meta.counter_reg1 = meta.counter_reg1 + 1;
        meta.counter_reg2 = meta.counter_reg2 + 1;

        // Write variable back to the register
        sketch0.write(meta.hash0, meta.counter_reg0);
        sketch1.write(meta.hash1, meta.counter_reg1);
        sketch2.write(meta.hash2, meta.counter_reg2);


    }

    //TODO 1: define the forwarding table
    table forwarding {

        key = {
            standard_metadata.ingress_port: exact;
        }

        actions = {
            set_egress_port;
            drop;
        }

        size = 8;

        default_action = drop();


    }



    apply {
        //TODO 6: define the pipeline logic
        forwarding.apply();
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
            sketch_count();
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