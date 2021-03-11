#include <rte_common.h>
#include "pcap.h"

void pcap_header_init(struct pcap_header *header, uint32_t snaplen)
{
    header->magic = 0xa1b2c3d4;
    header->major = 0x0002;
    header->minor = 0x0004;
    header->thiszone = 0;
    header->sigfigs = 0;
    header->snaplen = snaplen;
    header->linktype = 0x00000001; // Ethernet and Linux loopback
}
