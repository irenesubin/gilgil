#include "ip.h"
#include "ethernet.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

// ✅ enum 정의 추가
typedef enum {
    ARP_HDR_ETHER = 1
} ArpHdrType;

typedef enum {
    ARP_PRO_IP4 = 0x0800
} ArpProtoType;

typedef enum {
    ARP_OP_REQUEST = 1,
    ARP_OP_REPLY = 2
} ArpOp;

struct arp_hdr {
    uint16_t ar_hrd ;
    uint16_t ar_pro;
    uint8_t  ar_hln;
    uint8_t  ar_pln;
    uint16_t ar_op;

    uint8_t sender_mac[6];  // src_mac of Ethernet
    uint8_t sender_ip[4];   // src_ip of IP
    uint8_t target_mac[6];  // dst_mac of Ethernet
    uint8_t target_ip[4];   // dst_ip of IP
} __attribute__((packed));

static inline void set_arp_basic(struct arp_hdr* arp, ArpHdrType hrd, ArpProtoType pro, ArpOp op) {
    arp->ar_hrd = htons(hrd);
    arp->ar_pro = htons(pro);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op  = htons(op);
}