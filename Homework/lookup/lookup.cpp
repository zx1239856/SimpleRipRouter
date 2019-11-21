#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unordered_map>

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

typedef struct {
    uint32_t len;
    uint32_t if_index;
    uint32_t nexthop;
} SimpleEntry;

std::unordered_map<uint32_t, SimpleEntry> table_entries;


/**
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
  if(isInsert) {
    table_entries[addr].if_index = entry.if_index;
    table_entries[addr].nexthop = entry.nexthop;
    table_entries[addr].len = entry.len;
  } else {
    auto it = table_entries.find(addr);
    if(it != table_entries.end())
      table_entries.erase(it);
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index)
{
  addr = ntohl(addr);
  for(uint32_t i = 32; i > 0; --i) {
    uint32_t _addr = addr & (0xffffffff << (32 - i));
    auto it = table_entries.find(_addr);
    if(it != table_entries.end() && it->second.len == i) {
      *nexthop = it->second.nexthop;
      *if_index = it->second.if_index;
      return true;
    }
  }
  *nexthop = 0;
  *if_index = 0;
  return false;
}