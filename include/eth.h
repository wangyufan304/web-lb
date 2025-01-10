//
// Created by root on 1/9/25.
//

#ifndef WLB_ETH_H
#define WLB_ETH_H

#include "dpdk.h"
#include "common.h"
#include "list.h"
#include "nic.h"

typedef struct {
    uint16_t eth_type;
    const char *protocol_name;
} eth_protocol_map_t;

struct pkt_type {
    uint16_t type; /* htons(ether-type) */
    struct nic_port *port; /* NULL for wildcard */
    int (*func)(struct rte_mbuf *mbuf, struct nic_port *port);

    struct list_head list;
} __rte_cache_aligned;

struct hz_queue_conf {
    queueid_t id;
    uint16_t len;
    struct rte_mbuf *mbufs[1024];

};

struct hz_port_conf {
    portid_t id;
    struct hz_queue_conf *rx;
    struct hz_queue_conf *tx;
};

struct hz_lcore_conf {
    lcoreid_t id;
    wlb_cpu_lcore_role_t type;
    struct hz_port_conf *in;
    struct hz_port_conf *out;
};

void print_eth_protocol(uint16_t eth_type);

struct pkt_type *pkt_type_get(__be16 type, struct nic_port *port);

void pkt_type_register(struct pkt_type *pkt);

void init_eth(void);

#endif //WLB_ETH_H
