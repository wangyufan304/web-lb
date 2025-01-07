//
// Created by root on 1/6/25.
//

#ifndef WLB_NIC_H
#define WLB_NIC_H
#include "common.h"
#include "global_data.h"
#include "dpdk.h"
// 定义网卡抽象接口
struct nic_port{
    char nic_name[WLB_NIC_MAX_NAME];
    portid_t pid; /* port pid */
    int nrx_queue;
    int ntx_queue;
    uint16_t  flag;
    struct rte_ether_addr addr;
    int socket_id;
    uint16_t mtu;
    struct rte_mempool *mbuf_pool;
    struct rte_eth_conf dev_conf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_stats stats;
    rte_rwlock_t dev_lock;
}__rte_cache_aligned;

struct nic_lcore_stats
{
    uint64_t lcore_loop;        /* Total number of loops since start */
    uint64_t pktburst;          /* Total number of receive bursts */
    uint64_t zpktburst;         /* Total number of receive bursts with ZERO packets */
    uint64_t fpktburst;         /* Total number of receive bursts with MAX packets */
    uint64_t z2hpktburst;       /* Total number of receive bursts with [0, 0.5*MAX] packets */
    uint64_t h2fpktburst;       /* Total number of receive bursts with (0.5*MAX, MAX] packets */
    uint64_t ipackets;          /* Total number of successfully received packets. */
    uint64_t ibytes;            /* Total number of successfully received bytes. */
    uint64_t opackets;          /* Total number of successfully transmitted packets. */
    uint64_t obytes;            /* Total number of successfully transmitted bytes. */
    uint64_t dropped;           /* Total number of dropped packets by software. */
} __rte_cache_aligned;
int nic_port_init(void);
int nic_port_term(void);

int nic_port_start(struct nic_port *port);
struct nic_port* get_nic_ports(portid_t pid);
#endif //WLB_NIC_H
