#pragma once

#include <stdint.h>
#include <netinet/in.h>  

enum ether_type{
	Ip4 = 0x0800,
	Arp = 0x0806,
	Ip6 = 0x86DD
};

struct ethernet_hdr {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} __attribute__((packed));

// EtherType getter
static inline uint16_t get_ether_type(const struct ethernet_hdr* eth_hdr) {
    return ntohs(eth_hdr->ether_type);
}

// EtherType setter
static inline void set_ether_type(struct ethernet_hdr* eth_hdr, enum ether_type type) {
    eth_hdr->ether_type = htons(type);
}
