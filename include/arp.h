//
// Created by root on 1/9/25.
//

#ifndef WLB_ARP_H
#define WLB_ARP_H

#include "common.h"
#include "dpdk.h"
#include "list.h"
#include "global_data.h"

struct arp_table {
    rte_be32_t ip;
    struct rte_ether_addr addr;
    pid_t pid;
    struct list_head list;
}__rte_cache_aligned;

void add_arp_entry(rte_be32_t ip, const struct rte_ether_addr *mac, pid_t pid, int core_id);
void init_arp(void);
#endif //WLB_ARP_H