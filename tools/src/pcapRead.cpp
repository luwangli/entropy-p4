#include "../include/pcapRead.h"

#include <stdexcept>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <iostream>




    PcapRead::PcapRead(const std::string& pcap_filename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        mPcapHandler = pcap_open_offline(pcap_filename.c_str(), errbuf);
        if(mPcapHandler == nullptr)
            throw std::runtime_error("could not open pcap file'" + pcap_filename + "'");
        mLinkType = pcap_datalink(mPcapHandler);
    }

    PcapRead::~PcapRead(){
        pcap_close(mPcapHandler);
    }

    int PcapRead::nextPacket(PcapPacket& pcap_packet) {
        const int ret =pcap_next_ex(mPcapHandler,&pcap_packet.metadata,&pcap_packet.data);
        if(ret == -1)
            throw std::runtime_error(pcap_geterr(mPcapHandler));
        return ret;
    }
    std::size_t PcapRead::l2HeaderLength() const {
        uint16_t l2_header_length = 0;
        if (mLinkType == DLT_EN10MB){//ethernet type(10Mb,100Mb),header length is 14 Byte
            l2_header_length = 14;
            std::cout<<"DLT_EN"<<std::endl;
        } else if (mLinkType == DLT_C_HDLC)
            l2_header_length = 4;
        else if(mLinkType == 12 || mLinkType == DLT_IPV4)
            l2_header_length = 0;
        else
            throw std::runtime_error("unsupported link type: ? " + std::to_string(mLinkType));
        return l2_header_length;
    }

    uint16_t PcapRead::l2EtherType(const PcapPacket& pcap_packet) const {
        uint16_t ether_type = 0;
        if(mLinkType == DLT_EN10MB)
            ether_type = ntohs(*reinterpret_cast<const uint16_t*>(pcap_packet.data +12));
        else if(mLinkType == DLT_C_HDLC)
            ether_type = ntohs(*reinterpret_cast<const uint16_t*>(pcap_packet.data + 2));
        else if(mLinkType ==12|| mLinkType == DLT_IPV4)
            ether_type = ETHERTYPE_IP;
        else
            throw std::runtime_error("unsupported link type: eth: " + std::to_string(mLinkType));
        return ether_type;
    }

    uint32_t PcapRead::srcIpv4(const PcapPacket& pcap_packet) const {
        if(l2EtherType(pcap_packet) != ETHERTYPE_IP)
            throw std::runtime_error("could not extract source IPv4");
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(pcap_packet.data + l2HeaderLength());
        return ntohl(ip_header->ip_src.s_addr);
    }

    uint32_t PcapRead::dstIpv4(const PcapPacket& pcap_packet) const {
        if(l2EtherType(pcap_packet) != ETHERTYPE_IP)
            throw std::runtime_error("could not extract destination IPv4");
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(pcap_packet.data + l2HeaderLength());
        return ntohl(ip_header->ip_dst.s_addr);

    }

     uint32_t PcapRead::entropyPktNum(const PcapPacket& pcap_packet) const {
        if(l2EtherType(pcap_packet) != TYPE_ENTROPY)
            throw std::runtime_error("could not extract entropy information from packet");
        const struct entropy_t* entropy_header = reinterpret_cast<const struct entropy_t*>(pcap_packet.data + l2HeaderLength());
        /**********test***************/
    //    std::cout<<"pkt:"<<entropy_header->pkt_num<<std::endl;

        std::cout<<"ntohl pkt:"<<ntohl(entropy_header->pkt_num)<<std::endl;
        std::cout<<"ntohl entropy:"<<ntohl(entropy_header->src_entropy)<<std::endl;
    //    std::cout<<entropy_header->src_entropy<<std::endl;
        std::cout<<"type:"<<entropy_header->etherType<<std::endl;
    //    std::cout<<"nothl type"<<ntohl(entropy_header->etherType)<<std::endl;

        /*****************************/
        return ntohl(entropy_header->pkt_num);
     }
     uint32_t PcapRead::entropySrcEntropy(const PcapPacket& pcap_packet) const {
        if(l2EtherType(pcap_packet) != TYPE_ENTROPY)
            throw std::runtime_error("could not extract entropy information from packet");
        const struct entropy_t* entropy_header = reinterpret_cast<const struct entropy_t*>(pcap_packet.data + l2HeaderLength());
        std::cout<<ntohl(entropy_header->src_entropy)<<std::endl;
        return ntohl(entropy_header->src_entropy);

     }
     uint16_t PcapRead::entropyEtherType(const PcapPacket& pcap_packet) const {
        if(l2EtherType(pcap_packet) != TYPE_ENTROPY)
            throw std::runtime_error("could not extract entropy information from packet");
        const struct entropy_t* entropy_header = reinterpret_cast<const struct entropy_t*>(pcap_packet.data + l2HeaderLength());
        return ntohl(entropy_header->etherType);

     }
