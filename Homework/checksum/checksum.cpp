#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint32_t checkSum = 0;
  uint16_t* u16Packet = (uint16_t*) packet;
  uint8_t headerLen = (packet[0] & 0xf) << 1;
  uint16_t checkSumInPac = ntohs(u16Packet[5]);
  while(headerLen--) {
    checkSum += ntohs(*u16Packet++);
  }
  checkSum -= checkSumInPac;
  checkSum = (checkSum >> 16) + (checkSum & 0xffff);
  checkSum += (checkSum >> 16);
  return (uint16_t)(~checkSum) == checkSumInPac;
}