#include "router.h"
#include <string.h>

RipPacket REQUEST_RIP_PACKET = {
  1, RIP_REQUEST, {0, 0, 0, 0x10000000}
};

uint32_t constructRipRequest(uint8_t *buffer, in_addr_t src_ip) {
    uint32_t rip_len = assemble(&REQUEST_RIP_PACKET, buffer + 20 + 8);
    uint8_t header[28] = {
        0x45, 0xc0, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, // IP Header
        0x00, 0x00,             // Header checksum
        0x00, 0x00, 0x00, 0x00, // Source Addr
        0xe0, 0x00, 0x00, 0x09, // RIP Multicast Addr 224.0.0.9
        0x02, 0x08, 0x02, 0x08, // src, dst port 520
        0x00, 0x20, // length
        0x00, 0x00 // udp checksum
    };
    memcpy(buffer, header, 28 * sizeof(uint8_t));
    memcpy(buffer + 12, &src_ip, sizeof(in_addr_t));
    uint16_t headerCheckSum = getChecksum(buffer, 20);
    memcpy(buffer + 10, &headerCheckSum, sizeof(uint16_t));
    return rip_len + 20 + 8;
}

uint32_t constructRipResponse(uint8_t *buffer, in_addr_t src_ip, in_addr_t dst_ip, uint32_t out_if) {
  RipPacket packet;
  fillRipPacket(&packet, out_if);
  assemble(&packet, buffer + 28);
  uint8_t header[28] = {
        0x45, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, // IP Header
        0x00, 0x00,             // Header checksum
        0x00, 0x00, 0x00, 0x00, // Source Addr
        0x00, 0x00, 0x00, 0x00, // Dst Addr
        0x02, 0x08, 0x02, 0x08, // src, dst port 520
        0x00, 0x00, // length
        0x00, 0x00 // udp checksum
  };
  memcpy(buffer, header, 28 * sizeof(uint8_t));
  memcpy(buffer + 12, &src_ip, sizeof(in_addr_t));
  memcpy(buffer + 16, &dst_ip, sizeof(in_addr_t));
  uint16_t udpLen = 8 + 4 + 20 * packet.numEntries;
  uint16_t ipLen = 20 + udpLen;
  uint16_t udpLen_ = htons(udpLen);
  uint16_t ipLen_ = htons(ipLen);
  memcpy(buffer + 2, &ipLen_, sizeof(uint16_t));
  memcpy(buffer + 24, &udpLen_, sizeof(uint16_t));
  uint16_t headerCheckSum = getChecksum(buffer, 20);
  memcpy(buffer + 10, &headerCheckSum, sizeof(uint16_t));
  return ipLen;
}