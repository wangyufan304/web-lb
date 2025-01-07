/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
/**
 * netif unicast multicast hw address list setting.
 * XXX: currently, support multicast list only.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#ifndef __WLB_NETIF_ADDR_H__
#define __WLB_NETIF_ADDR_H__
#include "link_layer.h"
#include "nic.h"

int __netif_mc_add(struct nic_port *dev, const struct rte_ether_addr *addr);
int __netif_mc_del(struct nic_port *dev, const struct rte_ether_addr *addr);
int netif_mc_add(struct nic_port *dev, const struct rte_ether_addr *addr);
int netif_mc_del(struct nic_port *dev, const struct rte_ether_addr *addr);
void netif_mc_flush(struct nic_port *dev);
void netif_mc_init(struct nic_port *dev);
int __netif_mc_dump(struct nic_port *dev,
                    struct rte_ether_addr *addrs, size_t *naddr);
int netif_mc_dump(struct nic_port *dev,
                  struct rte_ether_addr *addrs, size_t *naddr);
int __netif_mc_print(struct nic_port *dev,
                     char *buf, int *len, int *pnaddr);
int netif_mc_print(struct nic_port *dev,
                   char *buf, int *len, int *pnaddr);

int __netif_mc_sync(struct nic_port *to, struct nic_port *from);
int netif_mc_sync(struct nic_port *to, struct nic_port *from);
int __netif_mc_unsync(struct nic_port *to, struct nic_port *from);
int netif_mc_unsync(struct nic_port *to, struct nic_port *from);

int __netif_mc_sync_multiple(struct nic_port *to, struct nic_port *from);
int netif_mc_sync_multiple(struct nic_port *to, struct nic_port *from);
int __netif_mc_unsync_multiple(struct nic_port *to, struct nic_port *from);
int netif_mc_unsync_multiple(struct nic_port *to, struct nic_port *from);

static inline int eth_addr_equal(const struct rte_ether_addr *addr1,
                                 const struct rte_ether_addr *addr2)
{
    const uint16_t *a = (const uint16_t *)addr1;
    const uint16_t *b = (const uint16_t *)addr2;

    return ((a[0]^b[0]) | (a[1]^b[1]) | (a[2]^b[2])) == 0;
}

static inline char *eth_addr_dump(const struct rte_ether_addr *ea,
                                  char *buf, size_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             ea->addr_bytes[0], ea->addr_bytes[1],
             ea->addr_bytes[2], ea->addr_bytes[3],
             ea->addr_bytes[4], ea->addr_bytes[5]);
    return buf;
}

#endif /* __WLB_NETIF_ADDR_H__ */
