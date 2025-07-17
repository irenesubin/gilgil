#include <stddef.h> // for size_t
#include <stdint.h> // for uint32_t
#include <stdlib.h> // for malloc
#include <stdio.h> // for printf
#include <netinet/in.h> // for htons, htonl

uint32_t  thousand() {
    uint32_t *network_buffer = malloc(sizeof(uint32_t)); 

    FILE* fp = fopen("thousand.bin", "rb");
    if (fp == NULL){
        perror("Error opening file");
        return 0;
    }

    size_t file_read = fread(network_buffer, sizeof(uint32_t), 1, fp);
    if (file_read != 1){
        perror("Error reading file");
        free(network_buffer);
        return 0;
    }

    fclose(fp);
	//printf("32 bit number=0x%x\n", *network_buffer);
     
    uint32_t th_val= ntohl(*network_buffer);
    free(network_buffer);
    return th_val;
}

uint32_t  five_hundred() {
    uint32_t *network_buffer = malloc(sizeof(uint32_t)); 

    FILE* fp = fopen("five-hundred.bin", "rb");
    if (fp == NULL){
        perror("Error opening file");
        return 0;
    }

    size_t file_read = fread(network_buffer, sizeof(uint32_t), 1, fp);
    if (file_read != 1){
        perror("Error reading file");
        free(network_buffer);
        return 0;
    }

    fclose(fp);
	//printf("32 bit number=0x%x\n", *network_buffer);
     
    uint32_t th_val= ntohl(*network_buffer);
    free(network_buffer);
    return th_val;
}

uint32_t  two_hundred() {
    uint32_t *network_buffer = malloc(sizeof(uint32_t)); 

    FILE* fp = fopen("two-hundred.bin", "rb");
    if (fp == NULL){
        perror("Error opening file");
        return 0;
    }

    size_t file_read = fread(network_buffer, sizeof(uint32_t), 1, fp);
    if (file_read != 1){
        perror("Error reading file");
        free(network_buffer);
        return 0;
    }

    fclose(fp);
	//printf("32 bit number=0x%x\n", *network_buffer);
     
    uint32_t th_val= ntohl(*network_buffer);
    free(network_buffer);
    return th_val;
}


void sum(){
    uint32_t th = thousand();
    uint32_t five_h = five_hundred();
    uint32_t two_h = two_hundred();
    uint32_t sum = th + five_h + two_h;
    printf("%u(0x%08x) + %u(0x%08x) + %u(0x%08x) = %u(0x%08x)\n", 
        th, th, five_h, five_h, two_h, two_h, sum, sum);
}

int main() {
	//thousand();
	//two_thousand();
	//five_thousand();
	sum();
}