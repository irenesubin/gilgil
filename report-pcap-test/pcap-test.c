#include "libnet-pcap-header.h"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"

typedef unsigned char u_char;

//error message
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

//struct type
typedef struct {
	char* dev_;
} Param;

//struct func
Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
        struct libnet_ethernet_hdr* ethernet;
        struct libnet_ipv4_hdr* ip;
        struct libnet_tcp_hdr* tcp;
        const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        //sizeof는 함수가 아니다.
        ethernet = (struct libnet_ethernet_hdr *)packet;
        ip = (struct libnet_ipv4_hdr*) (packet + sizeof(*ethernet));
        tcp = (struct libnet_tcp_hdr*) (packet + sizeof(*ethernet) + sizeof(*ip));
        
        //src MAC / dst MAC
        //EHTERTYPE IP
        printf("==========================\n");
        printf("<Ethernet>\n");
        printf("Dst MAC:");
        for(int i = 0; i < ETHER_ADDR_LEN; i++){
            if(i == ETHER_ADDR_LEN - 1) {
                printf("%02X\n",ethernet->ether_dhost[i]);
            }
            else{
                printf("%02X:",ethernet->ether_dhost[i]);
            }
        }
        
        printf("Src MAC:");
        for(int i = 0; i < ETHER_ADDR_LEN; i++){
            if(i == ETHER_ADDR_LEN - 1) {
                printf("%02X\n",ethernet->ether_shost[i]);
            }
            else{
                printf("%02X:",ethernet->ether_shost[i]);
            }
        } 
        
        //src ip / dst ip
        printf("<IP>\n");   
        printf("SRC IP: %s\n", inet_ntoa(ip ->ip_src));
        printf("DST IP: %s\n", inet_ntoa( ip ->ip_dst));

        //src port / dst port
        printf("<TCP>\n");
        u_int16_t tcp_src_val = tcp ->th_sport;
        printf("SRC TCP: %d\n", ntohs(tcp_src_val));
        u_int16_t tcp_dst_val = tcp ->th_dport;
        printf("DST TCP: %d\n", ntohs(tcp_dst_val));

        //Payload(Data)의 hexadecimal value(최대 20바이트까지만)
        uint32_t hsize = sizeof(*ethernet) + sizeof(*ip) + sizeof(*tcp);
        printf("<Payload(Data)> : ");
        for(int i = hsize; i < hsize + 20 && i < header->len; i++) {
            printf("0x%02X ",packet[i]);
        }
        printf("\n");

	}

	pcap_close(pcap);
}
