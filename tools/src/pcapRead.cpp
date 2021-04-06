#include "pcapRead.hpp"

#inclue <stdexcept>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

namespace ENTROPY {

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
        if(ret = -1)
            throw std::runtime_error(pcap_geterr(mPcapHandler));
        return ret;
    }
    std::size_t PcapRead::l2HeaderLength() const {
        uint16_t l2_header_length = 0;
        if(mLinkType == 12 || mLinkType == DLT_IPV4)
            l2_header_length = 0;
        else
            throw std::runtime_error("unsupported link type" + std::to_string(mLinkType));
        return l2_header_length;
    }

    uint16_t PcapRead::l2EtherType(cosnt PcapPacket& pcap_packet) const {
        uint16_t ether_type = 0;
        if(mLinkType ==12|| mLinkType == DLT_IPV4)
            ether_type = ETHERTYPE_IP;
        else
            throw std::runtime_error("unsupported link type" + std::to_string(mLinkType));
        return ether_type;
    }

    uint32_t PcapRead::srcIpv4(const PcapPacket& pcap_packet) const {
        if(l2EtherType(pcap_packet) != ETHERTYPE_IP)
            throw std::runtime_error("could not extract source IPv4");
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(pcap_packet.data + l2HeaderLength());
        return 
    }



}
