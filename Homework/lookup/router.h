#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "router_hal.h"
#include "rip.h"
#ifdef IGNORE_PRINTF
#define printf(fmt, ...) (0)
#endif

typedef struct {
    uint32_t addr;
    uint32_t len;
    uint32_t if_index;
    uint32_t nexthop;
    uint32_t metric;
} RoutingTableEntry;

#define MASK_TO_PREFIX_LEN(bin) (32 - __builtin_clz((bin)))
#define PREFIX_LEN_TO_MASK(len) (0xffffffff << (32 - len))

/**
 * Checksum Utils
 */
bool validateIPChecksum(uint8_t *packet, size_t len);
uint16_t getChecksum(uint8_t *buffer, size_t len);

/**
 * Forward Utils
 */
//bool forward(uint8_t *packet, size_t len);
bool directForward(uint8_t *packet, size_t len);

/**
 * Rest-In-Peace Utils
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
uint32_t constructRipRequest(uint8_t *buffer, in_addr_t src_ip);
uint32_t constructRipResponse(uint8_t *buffer, in_addr_t src_ip, in_addr_t dst_ip, uint32_t out_if);
void handleRipPacket(const RipPacket *rip, in_addr_t src);
void fillRipPacket(RipPacket *rip, uint32_t out_if_index);
/**
 * Routing tables
 */
RoutingTableEntry* queryExact(uint32_t addr, uint32_t prefix_len);
RoutingTableEntry* queryLongest(uint32_t addr, uint32_t prefix_len);
void printRoutingTable();
bool isDirectConnect(uint32_t addr);
/**
 * Miscs
 */
inline void extractAddrFromPacket(uint8_t *buffer, in_addr_t *src, in_addr_t *dst) {
    // here ip packet must be valid
    *src = *(in_addr_t*)(buffer + 12);
    *dst = *(in_addr_t*)(buffer + 16);
}