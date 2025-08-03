#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAC_ADDR_LEN 6

typedef struct {
    uint8_t addr[MAC_ADDR_LEN];
} Mac;

static const uint8_t NULL_MAC[MAC_ADDR_LEN] = {0, 0, 0, 0, 0, 0};
static const uint8_t BROADCAST_MAC[MAC_ADDR_LEN] = {255, 255, 255, 255, 255, 255};

// MAC 비교
static inline int mac_equal(const Mac* a, const Mac* b) {
    return memcmp(a->addr, b->addr, MAC_ADDR_LEN) == 0;
}

// Null MAC 여부
static inline int mac_is_null(const Mac* mac) {
    return memcmp(mac->addr, NULL_MAC, MAC_ADDR_LEN) == 0;
}

// 브로드캐스트 MAC 여부
static inline int mac_is_broadcast(const Mac* mac) {
    return memcmp(mac->addr, BROADCAST_MAC, MAC_ADDR_LEN) == 0;
}

// 멀티캐스트 MAC 여부 (01:00:5E:0* 조건)
static inline int mac_is_multicast(const Mac* mac) {
    return mac->addr[0] == 0x01 && mac->addr[1] == 0x00 &&
           mac->addr[2] == 0x5E && (mac->addr[3] & 0x80) == 0x00;
}

// MAC 클리어
static inline void mac_clear(Mac* mac) {
    memcpy(mac->addr, NULL_MAC, MAC_ADDR_LEN);
}

// MAC 복사
static inline void mac_copy(Mac* dst, const Mac* src) {
    memcpy(dst->addr, src->addr, MAC_ADDR_LEN);
}

// MAC 초기화 (바이트 배열 → 구조체)
static inline void mac_from_bytes(Mac* mac, const uint8_t* bytes) {
    memcpy(mac->addr, bytes, MAC_ADDR_LEN);
}

// MAC 출력
static inline void mac_print(const Mac* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac->addr[0], mac->addr[1], mac->addr[2],
           mac->addr[3], mac->addr[4], mac->addr[5]);
}

int get_mac_address(const char* if_name, uint8_t *mac_addr_buf);