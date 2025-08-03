#include "mac.h"

// C 스타일 MAC 주소 읽기 함수
int get_mac_address(const char* if_name, uint8_t *mac_addr_buf) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", if_name);

    FILE* fp = fopen(path, "r");
    if (!fp) return 0;

    char mac_str[18]; // "xx:xx:xx:xx:xx:xx" + null
    if (!fgets(mac_str, sizeof(mac_str), fp)) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    // MAC 문자열을 바이트 배열로 파싱
    int values[MAC_ADDR_LEN];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != MAC_ADDR_LEN) {
        return 0;
    }

    // 리틀엔디안 순서대로 값을 저장
    for (int i = 0; i < MAC_ADDR_LEN; i++) {
        mac_addr_buf[i] = (uint8_t) values[i]; // 순서 뒤집기
    }
    return 1;
}