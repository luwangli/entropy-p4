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
    bit<32> evict_ip_count;


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
    register<bit<8>>(1) R_log2_m;

    //observation window control parameters
    register<bit<32>>(1) R_ow_counter;
    register<bit<32>>(1) R_pkt_counter;

    // filter struct
    register<bit<32>>(FILTER_WIDTH) R_src_filter_key;
    register<bit<32>>(FILTER_WIDTH) R_src_filter_count;
    register<bit<32>>(FILTER_WIDTH) R_src_filter_vote;//initial value is 0; if reset, then 16
    //observation windows annotation in filter
    register<bit<8>>(FILTER_WIDTH) R_src_filter_ow;

    // count min sketch; 2^12 = 4096 in every counter
    register<bit<12>>(CM_WIDTH) R_src_cm1_count;
    register<bit<12>>(CM_WIDTH) R_src_cm2_count;
    register<bit<12>>(CM_WIDTH) R_src_cm3_count;
    register<bit<12>>(CM_WIDTH) R_src_cm4_count;
    //observation window annotation in count min sketch;
    register<bit<8>>(CM_WIDTH) R_src_cm1_ow;
    register<bit<8>>(CM_WIDTH) R_src_cm2_ow;
    register<bit<8>>(CM_WIDTH) R_src_cm3_ow;
    register<bit<8>>(CM_WIDTH) R_src_cm4_ow;

    //entropy
    register<bit<32>>(1) R_src_entropy;

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

    action countmin(in bit<12> x1, in bit<12> x2, in bit<12> x3, in bit<12> x4, out bit<32> y) {
        if (x1 <= x2 && x1 <= x3 && x1 <= x4)
            y = (bit<32>) x1;
        else if (x2<= x1 && x2<=x3 && x2 <= x4)
            y = (bit<32>) x2;
        else if (x3<= x1 && x3<= x2 && x3 <= x4)
            y = (bit<32>) x3;
        else
            y = (bit<32>) x4;
    }

    action get_minvalue_cm(in bit<32> h1, inout bit<12> count1, in bit<32> h2,
                            inout bit<12> count2, in bit<32> h3, inout bit<12> count3,
                            in bit<32> h4,inout bit<12> count4, in bit<32> current_ow) {
    //estimation in row 1
        bit<8> src_cm1_ow_aux;
        R_src_cm1_ow.read(src_cm1_ow_aux,h1);
        if(src_cm1_ow_aux != current_ow[7:0]) {
            count1 = 0;
            R_src_cm1_ow.write(h1, current_ow[7:0]);
        } else {
            R_src_cm1_count.read(count1, h1);//不一定是加1
        }

         //estimation in row 2
        bit<8> src_cm2_ow_aux;
        R_src_cm2_ow.read(src_cm2_ow_aux,h2);
        if(src_cm2_ow_aux != current_ow[7:0]) {
            count2 = 0;
            R_src_cm2_ow.write(h2, current_ow[7:0]);
        } else {
            R_src_cm2_count.read(count2, h2);//不一定是加1
        }
        //estimation in row 3
        bit<8> src_cm3_ow_aux;
        R_src_cm3_ow.read(src_cm3_ow_aux,h3);
        if(src_cm3_ow_aux != current_ow[7:0]) {
            count3 = 0;
            R_src_cm3_ow.write(h3, current_ow[7:0]);
        } else {
            R_src_cm3_count.read(count3, h3);//不一定是加1
        }
        //estimation in row 4
        bit<8> src_cm4_ow_aux;
        R_src_cm4_ow.read(src_cm4_ow_aux,h4);
        if(src_cm4_ow_aux != current_ow[7:0]) {
            count4 = 0;
            R_src_cm4_ow.write(h4, current_ow[7:0]);
        } else {
            R_src_cm4_count.read(count4, h4);//不一定是加1
        }


    }


    action filter_hash(in bit<32> ipv4_addr, out bit<32> h) {
        hash(h, HashAlgorithm.crc32, 32w0, {ipv4_addr}, 32w0xffffffff);
    }

    apply {
        if(hdr.ipv4.isValid()) {
            bit<32> current_ow;
            R_ow_counter.read(current_ow,0);

            bit<32> src_filter_h;
            filter_hash(hdr.ipv4.srcAddr, src_filter_h);

            bit<8> src_filter_ow_aux;
            R_src_filter_ow.read(src_filter_ow_aux, src_filter_h);

            /************************layer 1: filter **********************************************/
            bit<32> src_filter_count;
            bit<32> src_filter_vote;
            bit<32> src_filter_key;
            //if observation windows in filter is not equal to current windows; update filter structure
            //else, read correspongding register
            if(src_filter_ow_aux != current_ow[7:0]) {
                src_filter_count = 0;
                src_filter_vote = 0;
                R_src_filter_ow.write(src_filter_h, current_ow[7:0]);//update observation windows
            } else {
                R_src_filter_key.read(src_filter_key,src_filter_h);
                R_src_filter_count.read(src_filter_count,src_filter_h);
                R_src_filter_vote.read(src_filter_vote,src_filter_h);
            }

            if(src_filter_count == 0) {
            //case 1: start of a new observation windows
                src_filter_key = hdr.ipv4.srcAddr;
                src_filter_count = src_filter_count +1;
                src_filter_vote = src_filter_vote + 1;
                meta.ip_count = src_filter_count;
            } else if( src_filter_key == hdr.ipv4.srcAddr) {
                //case 2: incoming packet is belong to the flow in filter layer
                src_filter_count = src_filter_count + 1;
                src_filter_vote = src_filter_vote + 1;
                meta.ip_count = src_filter_count;
            } else {
            //incoming packet don't belong to the flow in filter layer
            /***************************layer2 : Count Min Sketch****************************/
                bit<32> src_cm1_h;
                bit<32> src_cm2_h;
                bit<32> src_cm3_h;
                bit<32> src_cm4_h;
                bit<12> src_cm1_count;
                bit<12> src_cm2_count;
                bit<12> src_cm3_count;
                bit<12> src_cm4_count;
                cm_hash(hdr.ipv4.srcAddr, src_cm1_h, src_cm2_h, src_cm3_h, src_cm4_h);
                //get_minvalue_cm(src_cm1_h, src_cm1_count,src_cm2_h,src_cm2_count,src_cm3_h,src_cm3_count,src_cm4_h,src_cm4_count,current_ow);

                /*************************************************************************/
                //conditional exception in action is not supported :(  https://github.com/p4lang/p4c/issues/644
                bit<8> src_cm1_ow_aux;
                R_src_cm1_ow.read(src_cm1_ow_aux,src_cm1_h);
                if(src_cm1_ow_aux != current_ow[7:0]) {
                    src_cm1_count = 0;
                    R_src_cm1_ow.write(src_cm1_h, current_ow[7:0]);
                } else {
                 R_src_cm1_count.read(src_cm1_count, src_cm1_h);//不一定是加1
                 }

                //estimation in row 2
                bit<8> src_cm2_ow_aux;
                R_src_cm2_ow.read(src_cm2_ow_aux,src_cm2_h);
                if(src_cm2_ow_aux != current_ow[7:0]) {
                    src_cm2_count = 0;
                    R_src_cm2_ow.write(src_cm2_h, current_ow[7:0]);
                } else {
                    R_src_cm2_count.read(src_cm2_count, src_cm2_h);//不一定是加1
                }
                //estimation in row 3
                bit<8> src_cm3_ow_aux;
                R_src_cm3_ow.read(src_cm3_ow_aux,src_cm3_h);
                if(src_cm3_ow_aux != current_ow[7:0]) {
                    src_cm3_count = 0;
                    R_src_cm3_ow.write(src_cm3_h, current_ow[7:0]);
                } else {
                    R_src_cm3_count.read(src_cm3_count, src_cm3_h);//不一定是加1
                }
                //estimation in row 4
                bit<8> src_cm4_ow_aux;
                R_src_cm4_ow.read(src_cm4_ow_aux,src_cm4_h);
                if(src_cm4_ow_aux != current_ow[7:0]) {
                    src_cm4_count = 0;
                    R_src_cm4_ow.write(src_cm4_h, current_ow[7:0]);
                } else {
                    R_src_cm4_count.read(src_cm4_count, src_cm4_h);//不一定是加1
                }
                /**************************************************************************/

                if( src_filter_vote > 0 ) {
                //case 3: incoming packet don't belong to the flow in filter, and the vote isn't zero
                //incoming packet insert into Count Min Sketch
                   src_cm1_count = src_cm1_count +1;
                   src_cm2_count = src_cm2_count +1;
                   src_cm3_count = src_cm3_count +1;
                   src_cm4_count = src_cm4_count +1;

                   R_src_cm1_count.write(src_cm1_h, src_cm1_count);
                   R_src_cm2_count.write(src_cm2_h, src_cm2_count);
                   R_src_cm3_count.write(src_cm3_h, src_cm3_count);
                   R_src_cm4_count.write(src_cm4_h, src_cm4_count);

                   countmin(src_cm1_count, src_cm2_count, src_cm3_count, src_cm4_count, meta.ip_count);
                }
                else {
                //case 4: incoming packet don't belong to the flow in filter, and the vote is zero;
                //which means that item should be exchange between layer1(filter) and layer2(Count Min Sketch)
                   //get the estimated value of incoming packet
                   src_cm1_count = src_cm1_count +1;
                   src_cm2_count = src_cm2_count +1;
                   src_cm3_count = src_cm3_count +1;
                   src_cm4_count = src_cm4_count +1;
                   countmin(src_cm1_count, src_cm2_count, src_cm3_count, src_cm4_count,  meta.ip_count);
                   //decrease incoming packet's value in CM
                   src_cm1_count = src_cm1_count - (bit<12>) meta.ip_count;
                   src_cm2_count = src_cm2_count - (bit<12>) meta.ip_count;
                   src_cm3_count = src_cm3_count - (bit<12>) meta.ip_count;
                   src_cm4_count = src_cm4_count - (bit<12>) meta.ip_count;

                   R_src_cm1_count.write(src_cm1_h, src_cm1_count);
                   R_src_cm2_count.write(src_cm2_h, src_cm2_count);
                   R_src_cm3_count.write(src_cm3_h, src_cm3_count);
                   R_src_cm4_count.write(src_cm4_h, src_cm4_count);

                   //the evict item in layer1 , add to cm
                   //first get corrsponding position; then get counter value
                   cm_hash(src_filter_key, src_cm1_h, src_cm2_h, src_cm3_h, src_cm4_h);
                   //get_minvalue_cm(src_cm1_h, src_cm1_count, src_cm2_h, src_cm2_count, src_cm3_h, src_cm3_count, src_cm4_h, src_cm4_count,current_ow);

                   /*************************************************************************/
                    //conditional exception in action is not supported :(
                    bit<8> src_cm1_ow_aux;
                    R_src_cm1_ow.read(src_cm1_ow_aux,src_cm1_h);
                    if(src_cm1_ow_aux != current_ow[7:0]) {
                        src_cm1_count = 0;
                        R_src_cm1_ow.write(src_cm1_h, current_ow[7:0]);
                    } else {
                    R_src_cm1_count.read(src_cm1_count, src_cm1_h);//不一定是加1
                    }

                    //estimation in row 2
                    bit<8> src_cm2_ow_aux;
                    R_src_cm2_ow.read(src_cm2_ow_aux,src_cm2_h);
                    if(src_cm2_ow_aux != current_ow[7:0]) {
                        src_cm2_count = 0;
                        R_src_cm2_ow.write(src_cm2_h, current_ow[7:0]);
                    } else {
                        R_src_cm2_count.read(src_cm2_count, src_cm2_h);//不一定是加1
                    }
                    //estimation in row 3
                    bit<8> src_cm3_ow_aux;
                    R_src_cm3_ow.read(src_cm3_ow_aux,src_cm3_h);
                    if(src_cm3_ow_aux != current_ow[7:0]) {
                        src_cm3_count = 0;
                        R_src_cm3_ow.write(src_cm3_h, current_ow[7:0]);
                    } else {
                        R_src_cm3_count.read(src_cm3_count, src_cm3_h);//不一定是加1
                    }
                    //estimation in row 4
                    bit<8> src_cm4_ow_aux;
                    R_src_cm4_ow.read(src_cm4_ow_aux,src_cm4_h);
                    if(src_cm4_ow_aux != current_ow[7:0]) {
                        src_cm4_count = 0;
                        R_src_cm4_ow.write(src_cm4_h, current_ow[7:0]);
                    } else {
                        R_src_cm4_count.read(src_cm4_count, src_cm4_h);//不一定是加1
                    }
                    /**************************************************************************/

                   countmin(src_cm1_count, src_cm2_count, src_cm3_count, src_cm4_count, meta.evict_ip_count);
                   src_cm1_count = src_cm1_count + (bit<12>) meta.evict_ip_count;
                   src_cm2_count = src_cm2_count + (bit<12>) meta.evict_ip_count;
                   src_cm3_count = src_cm3_count + (bit<12>) meta.evict_ip_count;
                   src_cm4_count = src_cm4_count + (bit<12>) meta.evict_ip_count;

                   R_src_cm1_count.write(src_cm1_h, src_cm1_count);
                   R_src_cm2_count.write(src_cm2_h, src_cm2_count);
                   R_src_cm3_count.write(src_cm3_h, src_cm3_count);
                   R_src_cm4_count.write(src_cm4_h, src_cm4_count);
                }
            }
            //update filter structure
            R_src_filter_key.write(src_filter_h,src_filter_key);
            R_src_filter_count.write(src_filter_h,meta.ip_count);
            R_src_filter_vote.write(src_filter_h,src_filter_vote);
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
