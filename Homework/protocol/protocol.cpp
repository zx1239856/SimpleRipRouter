#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unordered_map>
/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

extern std::unordered_map<uint32_t, RoutingTableEntry> table_entries;
/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output)
{
  // check ip packet length
  uint16_t *totalLenPtr = (uint16_t *)(packet + 2);
  uint16_t totalLen = ntohs(*totalLenPtr);
  if (totalLen > len || totalLen < 32) // at least 20 bytes + 8 bytes + 4 bytes
    return false;
  if (packet[9] != 0x11)  // is UDP protocol or not
    return false;
  uint16_t ipHeaderLen = (packet[0] & 0xf) << 2;
  uint16_t udpLen = ntohs(*(uint16_t*)(packet + ipHeaderLen + 4)); // skip src port, dst port
  if (totalLen - udpLen != ipHeaderLen)
    return false;
  uint16_t numRipEntries = (udpLen - 8 - 4) / 20; // 8 bytes UDP header, 4 bytes RIP header
  const uint8_t *ripPtr = packet + ipHeaderLen + 8;
  uint8_t command = ripPtr[0];
  uint8_t version = ripPtr[1];
  uint8_t unused_0 = ripPtr[2];
  uint8_t unused_1 = ripPtr[3];
  // only support rip v2
  // command - 1 request
  //         - 2 response
  if ((command == 1 || command == 2) && version == 2 && (unused_0 | unused_1) == 0 && numRipEntries <= RIP_MAX_ENTRY)
  {
    ripPtr += 4; // skip RIP header
    output->command = command;
    for (int i = 0; i < numRipEntries; ++i)
    {
      uint16_t addrFamily = *(uint16_t *)ripPtr;
      uint16_t routerTag = *(uint16_t *)(ripPtr + 2);
      uint32_t ipAddr = *(uint32_t *)(ripPtr + 4);
      uint32_t subnetMask = *(uint32_t *)(ripPtr + 8);
      uint32_t nextHop = *(uint32_t *)(ripPtr + 12);
      uint32_t metric = *(uint32_t *)(ripPtr + 16);
      // validate metric
      uint32_t _metric = ntohl(metric);
      if (_metric == 0 || _metric > 16)
        return false;
      // validate subnet mask
      bool hasOne = false;
      uint32_t _mask = ntohl(subnetMask);
      for (uint8_t i = 0; i < 32; ++i)
      {
        bool cur = _mask & 0x1;
        if (!hasOne && cur)
          hasOne = true;
        if (hasOne && !cur)
          return false; // invalid mask
        _mask >>= 1;
      }
      // check AF identifier
      uint16_t _addrFamily = ntohs(addrFamily);
      bool valid = ((command == 1 && _addrFamily == 0) || (command == 2 && _addrFamily == 2)) && !routerTag;
      if (!valid)
        return false;
      ripPtr += 20;
      output->entries[i].addr = ipAddr;
      output->entries[i].mask = subnetMask;
      output->entries[i].metric = metric;
      output->entries[i].nexthop = nextHop;
    }
    output->numEntries = numRipEntries;
  }
  else
    return false;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer)
{
  if(rip == nullptr)
    return 0;
  *buffer++ = rip->command;
  *buffer++ = 2;
  *buffer++ = 0;
  *buffer++ = 0;
  for(uint32_t i = 0; i < rip->numEntries; ++i) {
    *((uint16_t*)buffer) = htons(rip->command == 2 ? 2 : 0);  // AFI
    buffer += 2;
    *buffer++ = 0;
    *buffer++ = 0; // Router TAG
    *((uint32_t*)buffer) = rip->entries[i].addr;
    buffer += 4;
    *((uint32_t*)buffer) = rip->entries[i].mask;
    buffer += 4;
    *((uint32_t*)buffer) = rip->entries[i].nexthop;
    buffer += 4;
    *((uint32_t*)buffer) = rip->entries[i].metric;
    buffer += 4;
  }
  return 20 * rip->numEntries + 4;
}

void fillRipPacket(RipPacket *rip, uint32_t out_if_index) {
  if(rip == nullptr)
    return;
  int idx = 0;
  for(const auto& entry : table_entries) {
    bool need_poison = out_if_index == entry.second.if_index;
    uint32_t mask = PREFIX_LEN_TO_MASK(entry.second.len);
    uint32_t next_hop = htonl(entry.second.nexthop);
    rip->entries[idx].addr = htonl(entry.second.addr & mask);
    rip->entries[idx].mask = htonl(mask);
    rip->entries[idx].metric = htonl(need_poison ? 16 : std::min(entry.second.metric + 1, 16u));
    rip->entries[idx].nexthop = 0; // 0 means curr router
    if(idx++ == RIP_MAX_ENTRY)
      break;
  }
  rip->command = RIP_RESPONSE;
  rip->numEntries = idx;
}