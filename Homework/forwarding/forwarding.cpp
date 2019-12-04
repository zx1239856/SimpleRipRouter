#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  if(validateIPChecksum(packet, len)) {
    uint16_t oldTtl = packet[8] << 8;
    packet[8] -= 1;
    uint16_t* ckPtr = ((uint16_t*)packet) + 5;
    // RFC 1624 incremental update
    uint32_t checkSum = ~ntohs(*ckPtr) & 0xffff;
    checkSum += (~oldTtl & 0xffff) + (packet[8] << 8);
    checkSum = (checkSum >> 16) + (checkSum & 0xffff);
    checkSum += (checkSum >> 16);
    *ckPtr = htons(~((uint16_t)checkSum));
    return true;
  } else return false;
}

bool directForward(uint8_t *packet, size_t len) {
    uint16_t oldTtl = packet[8] << 8;
    packet[8] -= 1;
    if(packet[8] == 0)
      return false;
    uint16_t* ckPtr = ((uint16_t*)packet) + 5;
    // RFC 1624 incremental update
    uint32_t checkSum = ~ntohs(*ckPtr) & 0xffff;
    checkSum += (~oldTtl & 0xffff) + (packet[8] << 8);
    checkSum = (checkSum >> 16) + (checkSum & 0xffff);
    checkSum += (checkSum >> 16);
    *ckPtr = htons(~((uint16_t)checkSum));
    return true;
}