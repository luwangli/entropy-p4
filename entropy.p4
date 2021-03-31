#include <core.p4>
#include <v1model.p4>

//
#define FILTER_WIDTH 64
#define CM_WIDTH 2048

/***************************************HEADER**************************/
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> egressSpec_t;

const bit<16> TYPE_IPV4 = 0x800;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totallen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

struct metadata {
    bit<32> pkt_num; //the packet number within current windows
    bit<32> ip_count;//number of this ip, to caculate entropy
    bit<32> entropy_term;// the item entropy
    bit<32> src_entropy;


}

/***********************************PARSER *****************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************CHECKSUM************************/
control MyVerifyChecksum(inout headers hdr,
                        inout metadata meta) {
    apply{}
}

/****************INGRESS****************************/
control MyIngress (inout headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {


    //observation windows parameters
  //  register<bit<5>> log2_m;
    register<bit<8>>(1) log2_m;
    // filter struct
    register<bit<32>>(FILTER_WIDTH) src_filter;
    //windows annotation in filter
    register<bit<8>>(FILTER_WIDTH) src_filter_wa;

    // count min sketch; 2^12 = 4096 in every counter
    register<bit<12>>(CM_WIDTH) src_cm1;
    register<bit<12>>(CM_WIDTH) src_cm2;
    register<bit<12>>(CM_WIDTH) src_cm3;
    register<bit<12>>(CM_WIDTH) src_cm4;
    //window annotation in count min sketch;
    register<bit<8>>(CM_WIDTH) src_cm1_wa;
    register<bit<8>>(CM_WIDTH) src_cm2_wa;
    register<bit<8>>(CM_WIDTH) src_cm3_wa;
    register<bit<8>>(CM_WIDTH) src_cm4_wa;

    //entropy
    register<bit<32>>(1) src_S;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action get_entropy_term(bit<32> entropy_term) {
        meta.entropy_term = entropy_term;
    }

    table src_entropy_term {
        key = {
            meta.ip_count: lpm;
        }
        actions = {
            get_entropy_term;
        }
        default_action = get_entropy_term(0);
    }

    action cm_hash(in bit<32> ipv4_addr, out bit<32> h1, out bit<32> h2, out bit<32> h3, out bit<32> h4) {
        hash(h1, HashAlgorithm.h1, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(h2, HashAlgorithm.h2, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(h3, HashAlgorithm.h3, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(h4, HashAlgorithm.h4, 32w0, {ipv4_addr}, 32w0xffffffff);
    }

    action countmin(in bit<32> x1, in bit<32> x2, in bit<32> x3, in bit<32> x4, out bit<32> y) {
        if (x1 <= x2 && x1 <= x3 && x1 <= x4)
            y = x1;
        else if (x2<= x1 && x2<=x3 && x2 <= x4)
            y = x2;
        else if (x3<= x1 && x3<= x2 && x3 <= x4)
            y = x3;
        else
            y = x4;
    }

    apply {
        if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/***********************EGRESS***************************************************/
control MyEgress (inout headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata ) {
    apply{}
}

/**********************COMPUTE CHECKSUM**********************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply{
        update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}


/*******SWITCH****/
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;