#program once

#include <pcap.h>
#include <string.h>
#include <stdio.h>

typedef struct entropy_t {
    uint32_t pkt_num;
    uint32_t src_entropy;
    uint16_t etherType;
};


