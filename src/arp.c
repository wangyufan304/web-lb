//
// Created by root on 1/9/25.
//
#include "arp.h"
#include "schedule.h"
#include "global_data.h"
#include "eth.h"

extern struct hz_lcore_conf hz_lcore_conf[HZ_USE_MAX_CORE];

static void
init_core_arp_table(void) {
    int i;
    for (i = 0; i < HZ_USE_MAX_CORE; i++) {
        INIT_LIST_HEAD(&wlb_core_arp_table[i]);
    }
}

static void
init_arp_entry(struct arp_table *entry, rte_be32_t ip, const struct rte_ether_addr *mac, pid_t pid, int core_id) {
    entry->ip = ip;
    rte_ether_addr_copy(mac, &entry->addr);
    entry->pid = pid;
    list_add(&entry->list, &wlb_core_arp_table[core_id]);
}

// 添加 ARP 表项的函数
void add_arp_entry(rte_be32_t ip, const struct rte_ether_addr *mac, pid_t pid, int core_id) {
    struct arp_table *new_entry = rte_malloc_socket("struct arp_table", sizeof(struct arp_table), 0,
                                                    (int) rte_socket_id());
    init_arp_entry(new_entry, ip, mac, pid, core_id);
}

static void process_arp_request(struct rte_mbuf *mbuf, struct nic_port *port, const struct rte_ether_hdr *eth_request,
                                const struct rte_arp_hdr *arp_request) {
    struct rte_arp_hdr *arp_hdr;
    struct rte_ether_hdr *eth_hdr;
    lcoreid_t cid;
    portid_t pid;
    struct hz_queue_conf *tx_q;
    cid = rte_lcore_id();
    printf("cid=%d\n",cid);
    tx_q = hz_lcore_conf[cid].in->tx;
    *tx_q->mbufs = rte_pktmbuf_alloc(port->mbuf_pool);

    eth_hdr = rte_pktmbuf_mtod(*tx_q->mbufs, struct rte_ether_hdr*);
    arp_hdr = (struct rte_arp_hdr *) (eth_hdr + 1);

    rte_ether_addr_copy(&port->addr, &eth_hdr->s_addr);
    rte_ether_addr_copy(&eth_request->s_addr, &eth_hdr->d_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    arp_hdr->arp_hlen = arp_request->arp_hlen;
    arp_hdr->arp_plen = arp_request->arp_plen;
    arp_hdr->arp_protocol = arp_hdr->arp_protocol;
    arp_hdr->arp_data.arp_sip = arp_request->arp_data.arp_tip;
    arp_hdr->arp_data.arp_sip = arp_request->arp_data.arp_sip;

    rte_ether_addr_copy(&port->addr, &arp_hdr->arp_data.arp_sha);
    rte_ether_addr_copy(&arp_request->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);

    uint16_t arp_header_len = sizeof(struct rte_arp_hdr);
    uint16_t total_len = arp_header_len + rte_pktmbuf_pkt_len(mbuf) - sizeof(struct rte_ether_hdr);

    (*tx_q->mbufs)->pkt_len = total_len;
    (*tx_q->mbufs)->data_len = total_len - sizeof(struct rte_ether_hdr);
    tx_q->len = 1;
}

static int
process_arp(struct rte_mbuf *mbuf, struct nic_port *port) {
    struct rte_arp_hdr *arp_hdr;
    struct rte_ether_hdr *eth_hdr;
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    arp_hdr = (struct rte_arp_hdr *) (eth_hdr + 1);
    if (ntohs(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST) {
        printf("RTE_ARP_OP_REQUEST\n");
        process_arp_request(mbuf, port, eth_hdr,arp_hdr);
    }
    return 0;
}


static struct pkt_type arp_pkt = {
        .func= process_arp,
        .type = RTE_ETHER_TYPE_ARP,
        .port =NULL,
};

void init_arp(void) {
    pkt_type_register(&arp_pkt);
}
