#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>  

struct libnet_tcp_hdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
#if (LIBNET_LIL_ENDIAN)
    uint8_t th_x2:4, th_off:4;
#else
    uint8_t th_off:4, th_x2:4;
#endif
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};