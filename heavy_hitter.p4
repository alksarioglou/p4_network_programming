/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 32
#define PACKET_THRESHOLD 1000

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

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    //TODO 7.1: define the 4 metadata fields you need for bloom filter index and reading the values
    bit<32> hash_1;
    bit<32> hash_2;
    bit<32> register_1;
    bit<32> register_2;
    bit<1>  exceed_thres;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        //TODO 2: Define a parser for ethernet, ipv4 and tcp
        packet.extract(hdr.ethernet);
        packet.extract(hdr.ipv4);
        packet.extract(hdr.tcp);
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


    //TODO 6: define a counting bloom filter using a register
    register <bit<32>>(4096) bloom_filter;


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action update_bloom_filter(){
        //TODO 7: Define the update bloom filter action

        // Hash 1
        hash(meta.hash_1, 
        HashAlgorithm.crc16, 
        (bit<1>)0, 
        {hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol
        },(bit<16>)4096);

        // Hash 2
        hash(meta.hash_2, 
        HashAlgorithm.crc32, 
        (bit<1>)0, 
        {hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol
        },(bit<16>)4096);

        // Read registers and store values in metadata fields
        bloom_filter.read(meta.register_1, meta.hash_1);
        bloom_filter.read(meta.register_2, meta.hash_2);

        // Increase value of both variables by 1
        meta.register_1 = meta.register_1 + 1;
        meta.register_2 = meta.register_2 + 1;

        // Write values back to registers
        bloom_filter.write(meta.hash_1, meta.register_1);
        bloom_filter.write(meta.hash_2, meta.register_2);

    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

        //TODO 5: implement the forwarding action
        bit<48> tmpAddr;
        tmpAddr = hdr.ethernet.dstAddr; 
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = tmpAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

    }

    table ipv4_lpm {
        //TODO 4: define the l3 forwarding 
        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
        }

        size = 1024;
        default_action = drop();
    }

    apply {
        //TODO 8: implement the main logic
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
            update_bloom_filter();
            // Check if register values exceed the packet threshold
            if (meta.register_1 > PACKET_THRESHOLD && meta.register_2 > PACKET_THRESHOLD){
                drop();
            }
            else {
                ipv4_lpm.apply();
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
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        //TODO 9: update the checksum field
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
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
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //TODO 3: Deparse the ethernet, ipv4 and tcp headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);       
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