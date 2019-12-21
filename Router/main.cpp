#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <yaml-cpp/yaml.h>
#include "router_hal.h"
#include "router.h"

extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);

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
std::vector<std::string> if_names(N_IFACE_ON_BOARD);
const char *if_name_arr[N_IFACE_ON_BOARD];
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};
uint32_t prefix_len[N_IFACE_ON_BOARD] = {24, 24, 24, 24};
constexpr in_addr_t rip_group_addr = {0x090000e0}; // 224.0.0.9

void onInterrupt(int _)
{
  printf("SIGINT received, exiting...\n");
  HAL_Finalize(addrs, if_name_arr);
  exit(0);
}

bool parseIPv4Addr(const std::string &in, in_addr_t &addr, uint32_t &prefix) {
  size_t pos1 = in.find_first_of('.');
  if(pos1 == std::string::npos)
    return false;
  size_t pos2 = in.find_first_of('.', pos1 + 1);
  if(pos2 == std::string::npos)
    return false;
  size_t pos3 = in.find_first_of('.', pos2 + 1);
  if(pos3 == std::string::npos)
    return false;
  size_t pos4 = in.find_first_of('/', pos3 + 1);
  if(pos4 == std::string::npos)
    return false;
  auto seg0 = in.substr(0, pos1);
  auto seg1 = in.substr(pos1 + 1, pos2 - pos1 - 1);
  auto seg2 = in.substr(pos2 + 1, pos3 - pos2 - 1);
  auto seg3 = in.substr(pos3 + 1, pos4 - pos3 - 1);
  auto seg4 = in.substr(pos4 + 1);
  try {
    auto v0 = std::stoi(seg0);
    auto v1 = std::stoi(seg1);
    auto v2 = std::stoi(seg2);
    auto v3 = std::stoi(seg3);
    auto v4 = std::stoi(seg4);
    if(v0 < 0 || v0 > 255 || v1 < 0 || v1 > 255 || v2 < 0 || v2 > 255 || v3 < 0 || v3 > 255 || v4 < 0 || v4 > 32)
      return false;
    addr = ((v3 & 0xff) << 24) | ((v2 & 0xff) << 16) | ((v1 & 0xff) << 8) | ((v0 & 0xff));
    prefix = v4;
  } catch (std::invalid_argument) {
    return false;
  }
  return true;
}

int main(int argc, char *argv[])
{
  if(argc != 2) {
    printf("SimpleRipRouter by zx1239856.\nUsage: %s [config-file]\n", argv[0]);
    exit(0);
  }

  try {
    YAML::Node config = YAML::LoadFile(argv[1]);
    if(config["interfaces"] && config["interfaces"].Type() == YAML::NodeType::Sequence) {
      auto node = config["interfaces"];
      if(node.size() == N_IFACE_ON_BOARD) {
        for(size_t i = 0; i < N_IFACE_ON_BOARD; ++i) {
          if(node[i]["name"] && node[i]["ip"]) {
            if_names[i] = node[i]["name"].as<std::string>();
            if_name_arr[i] = if_names[i].c_str();
            auto ip = node[i]["ip"].as<std::string>();
            if(!parseIPv4Addr(ip, addrs[i], prefix_len[i])) {
              printf("Invalid ip address config: %s for interface %lu\n", ip.c_str(), i);
              exit(EXIT_FAILURE);
            }
          } else {
            printf("Invalid interface config detected. Should be {ip: ..., name: ....}\n");
            exit(EXIT_FAILURE);
          }
        }
      } else {
        printf("Only %d interfaces are supported, but %lu were provided.\n", N_IFACE_ON_BOARD, node.size());
        exit(EXIT_FAILURE);
      }
    } else {
      printf("Invalid yaml config file: %s.\nExpected `interfaces` key in file.\n", argv[1]);
      exit(EXIT_FAILURE);
    }
  }
  catch(YAML::ParserException) {
    printf("Invalid yaml config file: %s.\n", argv[1]);
    exit(EXIT_FAILURE);
  }
  catch(YAML::BadFile) {
    printf("Error opening config file: %s.\n", argv[1]);
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, onInterrupt);

  int res = HAL_Init(1, addrs, if_name_arr);
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
        .len = prefix_len[i],     // small endian
        .if_index = i, // small endian
        .nexthop = 0,
        .metric = 1};
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
      fprintf(stderr, "[Debug] Timer: send RIP response to multicast\n");
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; ++i)
      {
        macaddr_t dst_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};
        // uint32_t len = constructRipResponse(output, addrs[i], rip_group_addr, i);
        // HAL_SendIPPacket(i, output, len, dst_mac);
        sendRipResponse(output, addrs[i], rip_group_addr, i, dst_mac);
      }
      printRoutingTable();
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                              dst_mac, 1000, &if_index, true);
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

    res -= IP_OFFSET;
    auto ip_packet = packet + IP_OFFSET;

    if (!validateIPChecksum(ip_packet, res))
    {
      fprintf(stderr, "[Debug] Invalid IP Checksum, ignore\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    extractAddrFromPacket(ip_packet, &src_addr, &dst_addr);

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
      if (disassemble(ip_packet, res, &rip))
      {
        // disassemble success
        if (rip.command == RIP_REQUEST)
        {
          // request
          fprintf(stderr, "[Debug] Respond to RIP request from %d.%d.%d.%d\n",
                 src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff);
          // uint32_t len = constructRipResponse(output, addrs[if_index], src_addr, if_index);
          // HAL_SendIPPacket(if_index, output, len, src_mac);
          sendRipResponse(output, addrs[if_index], src_addr, if_index, src_mac);
        }
        else
        {
          // response
          fprintf(stderr, "[Debug] Obtained RIP response packet from %d.%d.%d.%d\n",
                 src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff);
          handleRipPacket(&rip, src_addr);
        }
      } else if(dst_is_me && ip_packet[9] == 0x01 && ip_packet[20] == 0x08) {
        // ICMP Ping request
        ip_packet[20] = 0x00; // ICMP ping reply
        memset(ip_packet + 22, 0, sizeof(uint16_t));
        uint16_t checksum = getChecksum(ip_packet + 20, res - 20);
        memcpy(ip_packet + 22, &checksum, sizeof(uint16_t));
        // ICMP checksum
        memcpy(ip_packet + 12, &dst_addr, sizeof(uint32_t));
        memcpy(ip_packet + 16, &src_addr, sizeof(uint32_t));
        // IP Header
        memset(ip_packet + 4, 0, sizeof(uint32_t));
        ip_packet[8] = 0x40;
        memset(ip_packet + 10, 0, sizeof(uint16_t));
        uint16_t headerCheckSum = getChecksum(ip_packet, 20);
        memcpy(ip_packet + 10, &headerCheckSum, sizeof(uint16_t));
        HAL_SendEthernetFrame(if_index, packet, res, src_mac);
        fprintf(stderr, "[Debug] Reply to ICMP ping from %d.%d.%d.%d\n",
          src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff);
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
          // update ttl and checksum
          if (directForward(ip_packet, res))
          {
            // zero copy
            HAL_SendEthernetFrame(dest_if, packet, res, dest_mac);
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
            uint8_t headerLen = (ip_packet[0] & 0xf) << 2;
            res = std::min(headerLen + 8, res);
            memcpy(icmp_buffer + 28, ip_packet, sizeof(uint8_t) * res);
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
        uint8_t headerLen = (ip_packet[0] & 0xf) << 2;
        res = std::min(headerLen + 8, res);
        memcpy(icmp_buffer + 28, ip_packet, sizeof(uint8_t) * res);
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
