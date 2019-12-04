#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unordered_map>

#define EXTRACT_ADDR(x) (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

std::unordered_map<uint32_t, RoutingTableEntry> table_entries;

/**
 * @deprecated
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool isInsert, RoutingTableEntry entry)
{
  uint32_t addr = ntohl(entry.addr) & (0xffffffff << (32 - entry.len));
  if (isInsert)
  {
    table_entries[addr] = {addr, entry.len, entry.if_index, ntohl(entry.nexthop), entry.metric};
  }
  else
  {
    auto it = table_entries.find(addr);
    if (it != table_entries.end())
      table_entries.erase(it);
  }
}

/**
 * @deprecated
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index)
{
  addr = ntohl(addr);
  for (uint32_t i = 32; i > 0; --i)
  {
    uint32_t _addr = addr & (0xffffffff << (32 - i));
    auto it = table_entries.find(_addr);
    if (it != table_entries.end() && it->second.len == i)
    {
      *nexthop = htonl(it->second.nexthop);
      *if_index = it->second.if_index;
      return true;
    }
  }
  *nexthop = 0;
  *if_index = 0;
  return false;
}

RoutingTableEntry *queryExact(uint32_t addr, uint32_t prefix_len)
{
  addr = ntohl(addr) & (0xffffffff << (32 - prefix_len));
  auto it = table_entries.find(addr);
  if (it != table_entries.end())
  {
    return &(it->second);
  }
  return nullptr;
}

RoutingTableEntry *queryLongest(uint32_t addr, uint32_t prefix_len)
{
  addr = ntohl(addr);
  for (uint32_t i = prefix_len; i > 0; --i)
  {
    uint32_t _addr = addr & (0xffffffff << (32 - i));
    auto it = table_entries.find(_addr);
    if (it != table_entries.end() && it->second.len == i)
    {
      return &(it->second);
    }
  }
  return nullptr;
}

bool isDirectConnect(uint32_t addr)
{
  auto res = queryLongest(addr, 32);
  if (res == nullptr)
    return false;
  return res->nexthop == 0;
}

void deleteRoute(uint32_t addr, uint32_t prefix_len)
{
  addr = ntohl(addr) & (0xffffffff << (32 - prefix_len));
  auto it = table_entries.find(addr);
  if (it != table_entries.end())
  {
    table_entries.erase(it);
  }
}

inline void updateRipRoute(RoutingTableEntry *entry, uint32_t new_metric, uint32_t new_next_hop)
{
  RoutingTableEntry *entry2 = queryLongest(new_next_hop, 32);
  if (entry2 == nullptr)
  {
    printf("[Warning] Failed to find entry for next_hop: %d.%d.%d.%d\n", EXTRACT_ADDR(ntohl(new_next_hop)));
    return;
  }
  else if (entry2->nexthop == 0)
  {
    return;
  }
  entry->nexthop = ntohl(new_next_hop);
  entry->metric = new_metric;
  entry->if_index = entry2->if_index;
}

void addRipRoute(uint32_t addr, uint32_t prefix_len, uint32_t next_hop, uint32_t metric)
{
  uint32_t addr_ = ntohl(addr) & (0xffffffff << (32 - prefix_len));
  RoutingTableEntry *entry = queryLongest(next_hop, 32);
  if (entry == nullptr)
  {
    printf("[Warning] Failed to find entry for next_hop: %d.%d.%d.%d\n", EXTRACT_ADDR(ntohl(next_hop)));
    return;
  }
  table_entries[addr_] = {ntohl(addr), prefix_len, entry->if_index, ntohl(next_hop), metric};
}

void printRoutingTable()
{
  printf("==============================Routing Table==============================\n");
  for (const auto &entry : table_entries)
  {
    if (entry.second.nexthop)
    {
      printf("%d.%d.%d.%d/%d\tvia %d.%d.%d.%d\t\tdev eth%d\tmetric %d\n",
             EXTRACT_ADDR(entry.second.addr), entry.second.len, EXTRACT_ADDR(entry.second.nexthop), entry.second.if_index, entry.second.metric);
    }
    else
    {
       printf("%d.%d.%d.%d/%d\t\tvia direct\t\tdev eth%d\tmetric %d\n",
             EXTRACT_ADDR(entry.second.addr), entry.second.len, entry.second.if_index, entry.second.metric);
    }
  }
  printf("=========================================================================\n");
}

#undef EXTRACT_ADDR

void handleRipPacket(const RipPacket *rip, in_addr_t src)
{
  if (!rip)
    return;
  for (uint32_t i = 0; i < rip->numEntries; ++i)
  {
    auto entry = rip->entries[i];
    if (entry.nexthop == 0)
      entry.nexthop = src; // means self
    uint32_t prefix_len = MASK_TO_PREFIX_LEN(entry.mask);
    uint32_t addr = entry.addr;
    uint32_t metric = ntohl(entry.metric) + 1;
    uint32_t next_hop = entry.nexthop;
    auto old_entry = queryExact(addr, prefix_len);
    if (old_entry == nullptr)
    {
      if (metric < RIP_INFINITY)
      {
        // new item
        addRipRoute(addr, prefix_len, next_hop, metric);
        printf("[Info] Added a new route from RIP response.\n");
        printRoutingTable();
      }
    }
    else
    {
      if (old_entry->nexthop == next_hop)
      {
        if (metric < RIP_INFINITY)
        {
          if (old_entry->metric != metric)
          {
            old_entry->metric = metric;
            printf("[Info] Updated route metric from RIP response.\n");
            printRoutingTable();
          }
        }
        else
        {
          deleteRoute(addr, prefix_len);
          printf("[Info] Deleted a route from RIP response.\n");
          printRoutingTable();
        }
      }
      else
      {
        // maybe an alternate route is available
        if (metric >= RIP_INFINITY)
        {
          // ignore
        }
        else if (metric < old_entry->metric)
        {
          printf("[Info] Updated to another route with smaller metric.\n");
          updateRipRoute(old_entry, metric, entry.nexthop);
          printRoutingTable();
        }
      }
    }
  }
}
