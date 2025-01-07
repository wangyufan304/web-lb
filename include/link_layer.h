#ifndef __WLB_LINK_LAYER_H__
#define __WLB_LINK_LAYER_H__

#include "common.h"
#include "global_data.h"
#include "dpdk.h"
#include "list.h"
/*
   cpu lcore conf: id, type, nports.
*/
struct nic_port;
struct nic_queue_conf
{
  queueid_t id;
  uint16_t len;
  struct rte_mbuf *mbufs[1024];
} __rte_cache_aligned;

struct nic_port_conf
{
  portid_t id;
  int nrx_queue;
  int ntx_queue;
  struct nic_queue_conf rx_queues[NIC_MAX_QUEUES];
  struct nic_queue_conf tx_queues[NIC_MAX_QUEUES];
} __rte_cache_aligned;

struct cpu_lcore_conf
{
  lcoreid_t id; // cpu lcore id
  wlb_cpu_lcore_role_t type;
  int nports;
  struct nic_port_conf pqs[NIC_MAX_RTE_PORT];
} __rte_cache_aligned;



struct  hz_queue_conf{
    queueid_t id;
    uint16_t len;
    struct rte_mbuf *mbufs[1024];

};

struct hz_port_conf{
    portid_t id;
    struct hz_queue_conf *rx;
    struct hz_queue_conf *tx;
};

struct  hz_lcore_conf{
    lcoreid_t id;
    wlb_cpu_lcore_role_t type;
    struct hz_port_conf *in;
    struct hz_port_conf *out;
};
struct pkt_type {
    uint16_t type; /* htons(ether-type) */
    struct  nic_port*port; /* NULL for wildcard */
    int (*func)(struct rte_mbuf *mbuf, struct nic_port *port);
    struct list_head list;
} __rte_cache_aligned;

typedef enum {
    ETH_PKT_HOST,
    ETH_PKT_BROADCAST,
    ETH_PKT_MULTICAST,
    ETH_PKT_OTHERHOST,
} eth_type_t;
int link_layer_init(void);
int link_layer_term(void);
void link_layer_init_port(portid_t pid,int nrx,int ntx);

#endif /* __WLB_LINK_LAYER_H__ */
