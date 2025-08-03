#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>  // for in_addr

enum protocol {
    ICMP = 1,
    TCP  = 6,
    UDP  = 17
};

struct ipv4_hdr {
    uint8_t ihl:4;       // Header Length (in 32-bit words)
    uint8_t version:4;   // IP Version (should be 4 for IPv4)

    uint8_t tos;         // Type of Service
    uint16_t total_len;  // Total Length (header + data)

    uint16_t id;         // Identification

    uint16_t frag_off;   // Flags (3 bits) + Fragment Offset (13 bits)

    uint8_t ttl;         // Time to Live
    uint8_t protocol;    // Protocol (e.g., TCP=6, UDP=17, etc.)
    uint16_t checksum;   // Header Checksum

    uint8_t src_ip[4];   // Source IP
    uint8_t dst_ip[4];   // Destination IP
} __attribute__((packed));

uint16_t get_ip_type(const struct ipv4_hdr* ip_hdr);
int get_ip_address(const char* iface, char* ip_str);
