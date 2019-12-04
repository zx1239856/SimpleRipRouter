#include "router_hal.h"
#include "router.h"
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>

extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);

uint8_t packet[2048];
uint8_t output[2048];
uint8_t icmp_buffer[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
// 192.168.2.2 for test
// 192.168.4.1 for test
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};
constexpr in_addr_t rip_group_addr = {0x090000e0}; // 224.0.0.9

void onInterrupt(int _)
{
  printf("SIGINT received, exiting...\n");
  HAL_Finalize(addrs);
  exit(0);
}

int main(int argc, char *argv[])
{
  signal(SIGINT, onInterrupt);

  int res = HAL_Init(1, addrs);
  if (res < 0)
  {
    return res;
  }

  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    RoutingTableEntry entry = {
        .addr = addrs[i],
        .len = 24,     // small endian
        .if_index = i, // small endian
        .nexthop = 0};
    update(true, entry);

    macaddr_t dst_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};
    uint32_t len = constructRipRequest(output, addrs[i]);
    HAL_SendIPPacket(i, output, len, dst_mac); // send RIP request on boot
  }

  printf("[Info] Initial routing table:\n");
  printRoutingTable();

  uint64_t last_time = 0;
  while (1)
  {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 15 * 1000)
    {
      last_time = time;
      printf("[Info] Timer: send RIP response to multicast\n");
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; ++i)
      {
        macaddr_t dst_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};
        uint32_t len = constructRipResponse(output, addrs[i], rip_group_addr, i);
        HAL_SendIPPacket(i, output, len, dst_mac);
      }
      printRoutingTable();
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                              dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF)
    {
      break;
    }
    else if (res < 0)
    {
      return res;
    }
    else if (res == 0)
    {
      // Timeout
      continue;
    }
    else if (res > sizeof(packet))
    {
      // packet is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res))
    {
      printf("Invalid IP Checksum, ignore\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    extractAddrFromPacket(packet, &src_addr, &dst_addr);

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++)
    {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
      {
        dst_is_me = true;
        break;
      }
    }
    // receive RIP group cast as well
    bool dst_is_rip_group = !memcmp(&rip_group_addr, &dst_addr, sizeof(in_addr_t));

    if (dst_is_me || dst_is_rip_group)
    {
      RipPacket rip;
      if (disassemble(packet, res, &rip))
      {
        // disassemble success
        if (rip.command == RIP_REQUEST)
        {
          // request
          printf("[Info] Respond to RIP request from %d.%d.%d.%d\n",
                 src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff);
          uint32_t len = constructRipResponse(output, addrs[if_index], src_addr, if_index);
          HAL_SendIPPacket(if_index, output, len, src_mac);
        }
        else
        {
          // response
          printf("[Info] Obtained RIP response packet from %d.%d.%d.%d\n",
                 src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff);
          handleRipPacket(&rip, src_addr);
        }
      }
    }
    else
    {
      // dst is not current router, can forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if))
      {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0)
        {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
        {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          if (directForward(output, res))
          {
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
          else
          {
            // ICMP time exceeded
            uint8_t new_buffer[28] = {
                0x45, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, // ip header
                0x0b, 0x00, 0x00, 0x00, // icmp
                0x00, 0x00, 0x00, 0x00};
            memcpy(icmp_buffer, new_buffer, sizeof(uint8_t) * 28);
            uint8_t headerLen = (packet[0] & 0xf) << 2;
            res = std::min(headerLen + 8, res);
            memcpy(icmp_buffer + 28, output, sizeof(uint8_t) * res);
            uint16_t new_len = 28 + res;
            uint16_t new_len_ = htons(new_len);
            memcpy(icmp_buffer + 2, &new_len_, sizeof(uint16_t));
            memcpy(icmp_buffer + 12, &addrs[if_index], sizeof(uint32_t));
            memcpy(icmp_buffer + 16, &src_addr, sizeof(uint32_t));
            uint16_t headerCheckSum = getChecksum(icmp_buffer, 20);
            uint16_t checksum = getChecksum(icmp_buffer + 20, res + 8);
            memcpy(icmp_buffer + 22, &checksum, sizeof(uint16_t));
            memcpy(icmp_buffer + 10, &headerCheckSum, sizeof(uint16_t));
            HAL_SendIPPacket(if_index, icmp_buffer, new_len, src_mac);
          }
        }
        else
        {
          // silently drop this packet
        }
      }
      else
      {
        // ICMP destination unreachable
        uint8_t new_buffer[28] = {
            0x45, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // ip header
            0x03, 0x00, 0x00, 0x00, // icmp
            0x00, 0x00, 0x00, 0x00};
        memcpy(icmp_buffer, new_buffer, sizeof(uint8_t) * 28);
        uint8_t headerLen = (packet[0] & 0xf) << 2;
        res = std::max(headerLen + 8, res);
        memcpy(icmp_buffer + 28, output, sizeof(uint8_t) * res);
        uint16_t new_len = 28 + res;
        uint16_t new_len_ = htons(new_len);
        memcpy(icmp_buffer + 2, &new_len_, sizeof(uint16_t));
        memcpy(icmp_buffer + 12, &addrs[if_index], sizeof(uint32_t));
        memcpy(icmp_buffer + 16, &src_addr, sizeof(uint32_t));
        uint16_t headerCheckSum = getChecksum(icmp_buffer, 20);
        uint16_t checksum = getChecksum(icmp_buffer + 20, res + 8);
        memcpy(icmp_buffer + 22, &checksum, sizeof(uint16_t));
        memcpy(icmp_buffer + 10, &headerCheckSum, sizeof(uint16_t));
        HAL_SendIPPacket(if_index, icmp_buffer, new_len, src_mac);
      }
    }
  }
  return 0;
}
