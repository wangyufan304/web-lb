#ifndef __WLB_LINK_LAYER_H__
#define __WLB_LINK_LAYER_H__

#include "common.h"
#include "global_data.h"
#include "dpdk.h"
#include "list.h"
#include "eth.h"

/*
   cpu lcore conf: id, type, nports.
*/
struct nic_port;




typedef enum {
    ETH_PKT_HOST,
    ETH_PKT_BROADCAST,
    ETH_PKT_MULTICAST,
    ETH_PKT_OTHERHOST,
} eth_type_t;

int link_layer_init(void);

int link_layer_term(void);

void link_layer_init_port(portid_t pid, int nrx, int ntx);

#endif /* __WLB_LINK_LAYER_H__ */
