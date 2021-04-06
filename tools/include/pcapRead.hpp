#program once

#include <pcap.h>
#include <string.h>
#include <stdio.h>

#define TYPE_ENTROPY 0x0700

namespace ENTROPY{
    typedef struct entropy_t {
        uint32_t pkt_num;
        uint32_t src_entropy;
        uint16_t etherType;
    };

    struct PcapPacket {
        struct pcap_pkthdr* metadata;
        const u_char* data;
    };

    class PcapRead {
        public:
            PcapRead(const std::string& pcap_filtename);
            PcapRead(const PcapRead&) = delete;
            PcapRead& operator=(const PcapRead&) = delete;

            ~PcapRead();

            int nextPacket(PcapPacket& pcap_packet);
            uint32_t srcIpv4(const PcapPacket& pcap_packet) const;
            uint32_t dstIpv4(const PcapPacket& pcap_packet) const;

            uint32_t entropyPktNum(const PcapPacket& pcap_packet) const;
            uint32_t entropySrcEntropy(const PcapPacket& pcap_packet) const;
            uint16_t entropyEtherType(const PcapPacket& pcap_packet) const;

        private:
            pcap_t* mPcapHandler;
            int mLinkType;//data layer protocol

            std::size_t l2HeaderLength() const;
            uint16_t l2EtherType(const PcapPacket& pcap_packet) const;


    };

}

typedef struct entropy_t {
    uint32_t pkt_num;
    uint32_t src_entropy;
    uint16_t etherType;
};


