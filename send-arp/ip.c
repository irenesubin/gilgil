#include "ip.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

uint16_t get_ip_type(const struct ipv4_hdr* ip_hdr) {
    return ip_hdr->protocol;
}

int get_ip_address(const char *iface, char *ip_str) {
    FILE *fp;
    char buffer[256];
    char command[64];

    snprintf(command, sizeof(command), "ip -f inet addr show %s", iface);

    fp = popen(command, "r");
    if (fp == NULL) return 0;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, "inet ")) {
            sscanf(buffer, " inet %15s", ip_str);
            char *slash = strchr(ip_str, '/');
            if (slash) *slash = '\0'; // CIDR 제거
            pclose(fp);
            return 1;
        }
    }

    pclose(fp);
    return 0;
}
