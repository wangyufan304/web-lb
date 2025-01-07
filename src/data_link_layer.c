#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "common.h"
#include "schedule.h"
#include "link_layer.h"
#include "tools.h"
#include "nic.h"
#include "netif_addr.h"
#define LINK_LAYER_PKTPOOL_NB_MBUF_DEF 65535
#define LINK_LAYER_PKTPOOL_MBUF_CACHE_DEF 256

int link_layer_pktpool_nb_mbuf = LINK_LAYER_PKTPOOL_NB_MBUF_DEF;
int link_layer_pktpool_mbuf_cache = LINK_LAYER_PKTPOOL_MBUF_CACHE_DEF;

struct rte_mempool *hzpktmbuf_pool[WLB_MAX_SOCKET];
static struct cpu_lcore_conf lcore_conf[WLB_MAX_LCORE + 1];
static struct nic_lcore_stats lcore_stats[WLB_MAX_LCORE];
static struct hz_lcore_conf hz_lcore_conf[8];
static struct pkt_type *hz_pkt_types[WLB_MAX_NIC_PORTS][WLB_MAX_ETH_TYPE];

static void print_ether_addr(struct rte_ether_addr *addr) {
    // 使用 printf 打印以太网地址，格式为 XX:XX:XX:XX:XX:XX
    printf("MAC Address: ");
    for (int i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
        printf("%02x", addr->addr_bytes[i]);
        if (i < RTE_ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf("\n");
}

static inline void
link_layer_hzpktbuf_pool_init(void) {
    int i;
    char pool_name[32];
    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(pool_name, sizeof(pool_name), "hz_mbuf_pool_%d", i);
        hzpktmbuf_pool[i] = rte_pktmbuf_pool_create(pool_name, link_layer_pktpool_nb_mbuf,
                                                    link_layer_pktpool_mbuf_cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, i);
        if (!hzpktmbuf_pool[i])
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d", i);
    }
}

static inline eth_type_t eth_type_parse(const struct rte_ether_hdr *eth_hdr,
                                        const struct nic_port *dev)
{
    if (eth_addr_equal(&dev->addr, &eth_hdr->d_addr))
        return ETH_PKT_HOST;

    if (rte_is_multicast_ether_addr(&eth_hdr->d_addr)) {
        if (rte_is_broadcast_ether_addr(&eth_hdr->d_addr))
            return ETH_PKT_BROADCAST;
        else
            return ETH_PKT_MULTICAST;
    }

    return ETH_PKT_OTHERHOST;
}
static inline uint16_t link_layer_rx_burst(portid_t pid, struct hz_queue_conf *qconf) {

    int nrx = 0;
    nrx = rte_eth_rx_burst(pid, rte_lcore_id(), qconf->mbufs, 1024);
    qconf->len = nrx;
    return nrx;
}
static struct pkt_type *pkt_type_get(__be16 type, struct nic_port *port)
{
    for(int i=0;i<NIC_MAX_RTE_PORT;i++)
       for(int j = 0;j<WLB_MAX_ETH_TYPE;j++){
        if(hz_pkt_types[i][j]!=NULL&&hz_pkt_types[i][j]->port->pid ==port->pid&&hz_pkt_types[i][j]->type==type){
            return hz_pkt_types[i][j];
        }
    }
    return NULL;
}
// 发送 ICMP Echo Reply
int send_ping_reply(struct rte_mbuf *req_mbuf, struct nic_port *port) {
    struct rte_ether_hdr *eth_hdr_req = rte_pktmbuf_mtod(req_mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip_hdr_req = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(req_mbuf, uint8_t *) + sizeof(struct rte_ether_hdr));
    struct rte_icmp_hdr *icmp_hdr_req = (struct rte_icmp_hdr *)((uint8_t *)ip_hdr_req + (ip_hdr_req->version_ihl & 0x0f) * 4);

    // 创建新的回复数据包
    struct rte_mbuf *reply_mbuf = rte_pktmbuf_alloc(port->mbuf_pool);
    if (!reply_mbuf) {
        printf("Failed to allocate mbuf for ping reply\n");
        return -1;
    }

    // 填充 Ethernet header
    struct rte_ether_hdr *eth_hdr_reply = rte_pktmbuf_mtod(reply_mbuf, struct rte_ether_hdr *);
    rte_ether_addr_copy(&eth_hdr_req->d_addr, &eth_hdr_reply->s_addr);  // Source MAC -> Destination MAC
    rte_ether_addr_copy(&eth_hdr_req->s_addr, &eth_hdr_reply->d_addr);  // Destination MAC -> Source MAC
    eth_hdr_reply->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);

    // 填充 IP header
    struct rte_ipv4_hdr *ip_hdr_reply = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(reply_mbuf, uint8_t *) + sizeof(struct rte_ether_hdr));
    memset(ip_hdr_reply, 0, sizeof(struct rte_ipv4_hdr));
    ip_hdr_reply->version_ihl = 0X45;
    ip_hdr_reply->type_of_service=0;
    ip_hdr_reply->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + rte_pktmbuf_pkt_len(req_mbuf) - sizeof(struct rte_ether_hdr));
    ip_hdr_reply->time_to_live = 64;
    ip_hdr_reply->next_proto_id = IPPROTO_ICMP;
    ip_hdr_reply->src_addr = ip_hdr_req->dst_addr;  // Source -> Destination
    ip_hdr_reply->dst_addr = ip_hdr_req->src_addr;  // Destination -> Source
    ip_hdr_reply->packet_id = 0 ;
    ip_hdr_reply->hdr_checksum = 0;
    ip_hdr_reply->hdr_checksum = rte_ipv4_cksum(ip_hdr_reply);

    // 填充 ICMP header
    struct rte_icmp_hdr *icmp_hdr_reply = (struct rte_icmp_hdr *)((uint8_t *)ip_hdr_reply + sizeof(struct rte_ipv4_hdr));
    memset(icmp_hdr_reply, 0, sizeof(struct rte_icmp_hdr));
    icmp_hdr_reply->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp_hdr_reply->icmp_code = 0;
    icmp_hdr_reply->icmp_ident = icmp_hdr_req->icmp_ident;
    icmp_hdr_reply->icmp_seq_nb = icmp_hdr_req->icmp_seq_nb;

    // 计算 ICMP 校验和
    uint16_t icmp_checksum = rte_ipv4_udptcp_cksum(ip_hdr_reply,icmp_hdr_reply);
    icmp_hdr_reply->icmp_cksum = rte_cpu_to_be_16(icmp_checksum);

    // 发送 ICMP Echo Reply 数据包
    struct hz_queue_conf *txcq =  hz_lcore_conf[rte_lcore_id()].in->tx;
    txcq->len = reply_mbuf->pkt_len;
    int sent = rte_eth_tx_burst(1, 1, &reply_mbuf,1) ;  // 发送到网卡的第一个队列
    if (sent == 0) {
        printf("Failed to send ping reply:%s\n", rte_strerror(rte_errno));
        rte_pktmbuf_free(reply_mbuf);
        return -1;
    }

    printf("Ping reply sent successfully\n");
    return 0;
}

#define PRINT_PACKET_HEADER(mbuf) \
    printf("Packet size: %d\n", rte_pktmbuf_pkt_len(mbuf)); \
    printf("Ethernet header:\n"); \
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *); \
    printf("    Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", \
            eth_hdr->s_addr.addr_bytes[0], eth_hdr->s_addr.addr_bytes[1], \
            eth_hdr->s_addr.addr_bytes[2], eth_hdr->s_addr.addr_bytes[3], \
            eth_hdr->s_addr.addr_bytes[4], eth_hdr->s_addr.addr_bytes[5]); \
    printf("    Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", \
            eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1], \
            eth_hdr->d_addr.addr_bytes[2], eth_hdr->d_addr.addr_bytes[3], \
            eth_hdr->d_addr.addr_bytes[4], eth_hdr->d_addr.addr_bytes[5]);
static int
link_layer_rcv_mbuf(struct nic_port * dev,lcoreid_t cid,struct rte_mbuf * mbuf) {
    struct rte_ether_hdr *eth_hdr;
    struct pkt_type *pt;
    int err;
    uint16_t data_off;
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
//    print_ether_addr(&eth_hdr->s_addr);
//    printf("%d-%d\n", rte_cpu_to_be_16(eth_hdr->ether_type),RTE_ETHER_TYPE_IPV4);

    if(rte_cpu_to_be_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4){
        PRINT_PACKET_HEADER(mbuf);

        // 获取IP头部
        struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(mbuf, uint8_t *) + sizeof(struct rte_ether_hdr));
        if (ip_hdr->next_proto_id != IPPROTO_ICMP) {
            printf("Not an ICMP packet\n");
            return -1;
        }
        // 获取ICMP头部
        struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)((uint8_t *)ip_hdr + (ip_hdr->version_ihl & 0x0f) * 4);
        printf("ICMP Packet: Type: %d, Code: %d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);

        if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
            printf("Ping Request (Echo Request):\n");
            printf("    Identifier: %d\n", ntohs(icmp_hdr->icmp_ident));
            printf("    Sequence Number: %d\n", ntohs(icmp_hdr->icmp_seq_nb));
            send_ping_reply(mbuf, dev);
        } else if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REPLY) {
            printf("Ping Reply (Echo Reply):\n");
            printf("    Identifier: %d\n", ntohs(icmp_hdr->icmp_ident));
            printf("    Sequence Number: %d\n", ntohs(icmp_hdr->icmp_seq_nb));
        } else {
            printf("Unknown ICMP Type: %d\n", icmp_hdr->icmp_type);
        }

    }
    pt = pkt_type_get(eth_hdr->ether_type, dev);
    if (NULL == pt) {
        goto drop;
    }
    mbuf->l2_len = sizeof(struct rte_ether_hdr);

    data_off = mbuf->data_off;
    if (unlikely(NULL == rte_pktmbuf_adj(mbuf, sizeof(struct rte_ether_hdr))))
        goto drop;

    if(eth_hdr->ether_type == RTE_ETHER_TYPE_IPV4){
        PRINT_PACKET_HEADER(mbuf);

        // 获取IP头部
        struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(mbuf, uint8_t *) + sizeof(struct rte_ether_hdr));
        if (ip_hdr->next_proto_id != IPPROTO_ICMP) {
            printf("Not an ICMP packet\n");
            return -1;
        }

    }
drop:
    rte_pktmbuf_free(mbuf);
    lcore_stats[cid].dropped++;
    return EWLB_DROP;
}
static int
link_layer_deliver_mbuf(struct nic_port * dev,lcoreid_t cid,struct rte_mbuf * mbuf){
    int ret = EWLB_OK;
    struct rte_ether_hdr *eth_hdr;

    assert(mbuf->port <= NIC_MAX_RTE_PORT);
    assert(dev != NULL);

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    /* reuse mbuf.packet_type, it was RTE_PTYPE_XXX */
    mbuf->packet_type = eth_type_parse(eth_hdr, dev);
    return link_layer_rcv_mbuf(dev, cid, mbuf);
}
static void lcore_process_packets(struct rte_mbuf **mbufs, lcoreid_t cid, uint16_t count) {
    int i,j;
    for(j = 0;j<count;++j){
        rte_prefetch0(rte_pktmbuf_mtod(mbufs[j],void*));
    }
    for(i = 0;i<count;i++){
        struct  rte_mbuf *mbuf = mbufs[i];
        struct nic_port *dev = get_nic_ports(mbuf->port);
        if(unlikely(!dev)){
            rte_pktmbuf_free(mbuf);
            lcore_stats[cid].dropped++;
            continue;
        }
        mbuf->tx_offload = 0;
        if(j <count){
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[j],void*));
            j++;
        }
        link_layer_deliver_mbuf(dev,cid,mbuf);
    }

}

static void lcore_job_recv_fwd(void *arg) {
    int i, j;
    lcoreid_t cid;
    portid_t pid;
    cid = rte_lcore_id();
//    for (i = 0; i < lcore_conf[cid].nports; i++) {
//        pid = lcore_conf[cid].pqs[i].id;
//        for (j = 0; j < lcore_conf[cid].pqs[i].nrx_queue; j++) {
//            qconf = &lcore_conf[cid].pqs[i].rx_queues[j];
//            qconf->len = link_layer_rx_burst(pid, qconf);
//            lcore_process_packets(qconf->mbufs, cid, qconf->len);
//        }
//    }
//    pid = hz_lcore_conf[cid].id;
//    int nrx;
//    struct rte_mbuf *mbufs[1024];
//    unsigned num_recvd = rte_eth_rx_burst(1, cid, mbufs, 1024);
//    if (num_recvd > 1024) {
//        rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
//    }
//    for (i = 0;i < num_recvd;i ++) {
//        struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
//        if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
//            continue;
//        }
//        print_ether_addr(&ehdr->s_addr);
//    }
//    nrx = rte_eth_rx_burst(hz_lcore_conf[cid].in.id, hz_lcore_conf[cid].in.rx.id,mbuf, 1024);
//    lcore_process_packets(hz_lcore_conf[cid].in.rx.mbufs, cid, hz_lcore_conf[cid].in.rx.len);
    pid = hz_lcore_conf[cid].in->id;
    hz_lcore_conf[cid].in->rx->len = link_layer_rx_burst(pid, hz_lcore_conf[cid].in->rx);
    lcore_process_packets(hz_lcore_conf[cid].in->rx->mbufs, cid, hz_lcore_conf[cid].in->rx->len);
}


#define LINK_LAYER_MAX_JOB 1
static struct wlb_lcore_job_array link_layer_jobs[LINK_LAYER_MAX_JOB] = {
        [0] = {
                .role = LCORE_ROLE_FWD_WORKER,
                .job.name = "recv_fwd",
                .job.func = lcore_job_recv_fwd,
        },
};

// hz_queue_conf 结构初始化
static void init_hz_queue_conf(struct hz_queue_conf *queue, queueid_t id, uint16_t len) {
    queue->id = id;
    queue->len = len;
    for (int i = 0; i < queue->len; i++) {
        queue->mbufs[i] = NULL;  // 初始为空
    }
}

// hz_port_conf 结构初始化
static void init_hz_port_conf(struct hz_port_conf *port, portid_t id) {
    port->id = id;
    // 初始化接收队列和发送队列
    init_hz_queue_conf(&port->rx, 0, 1024);
    init_hz_queue_conf(&port->tx, 1, 1024);
}

// hz_lcore_conf 结构初始化
static void init_hz_lcore_conf(struct hz_lcore_conf *lcore_conf, lcoreid_t id) {
    lcore_conf->id = id;
    lcore_conf->type = LCORE_ROLE_IDLE;  // 默认为空闲
    // 初始化输入端口和输出端口
    init_hz_port_conf(&lcore_conf->in, 0);
    init_hz_port_conf(&lcore_conf->out, 1);
}


int
link_layer_init(void) {
    int err;
    link_layer_hzpktbuf_pool_init();
    int qid = 0;
    for (int i = 0; i < WLB_MAX_LCORE; ++i) {
        lcore_conf[i].id = i;
        lcore_conf[i].type = LCORE_ROLE_NO_USED;
        g_lcore_role[i] = LCORE_ROLE_NO_USED;
        lcore_conf[i].nports = 2;
        for (int j = 0; j < 2; j++) {
            lcore_conf[i].pqs[j].id = j;
            lcore_conf[i].pqs[j].nrx_queue = NIC_MAX_PKT_BURST;
            lcore_conf[i].pqs[j].ntx_queue = NIC_MAX_PKT_BURST;
            for (int jj = 0; jj < lcore_conf[j].pqs[j].nrx_queue; jj++) {
//                lcore_conf[i].pqs[j].rx_queues[jj].id=qid++;
            }
            for (int jj = 0; jj < lcore_conf[j].pqs[j].ntx_queue; jj++) {
//                lcore_conf[i].pqs[j].tx_queues[jj].id=qid++;
            }
        }

    }
    for (int i = 0; i < 8; i++) {
        lcore_conf[i].type = LCORE_ROLE_FWD_WORKER;
        g_lcore_role[i] = LCORE_ROLE_FWD_WORKER;
        for (int j = 0; j < 2; j++) {
            for (int jj = 0; jj < lcore_conf[i].pqs[j].nrx_queue; jj++) {
                lcore_conf[i].pqs[j].rx_queues[jj].id = qid;
                for (int jjj = 0; jjj < NIC_MAX_PKT_BURST; jjj++) {
                    lcore_conf[i].pqs[j].rx_queues[jj].mbufs[jjj] = rte_pktmbuf_alloc(hzpktmbuf_pool[0]);
                    assert(lcore_conf[i].pqs[j].rx_queues[jj].mbufs[jjj] != NULL);
                }
            }
            for (int jj = 0; jj < lcore_conf[i].pqs[j].ntx_queue; jj++) {
                for (int jjj = 0; jjj < NIC_MAX_PKT_BURST; jjj++) {
                    lcore_conf[i].pqs[j].tx_queues[jj].mbufs[jjj] = rte_pktmbuf_alloc(hzpktmbuf_pool[0]);
                    assert(lcore_conf[i].pqs[j].tx_queues[jj].mbufs[jjj] != NULL);
                }
            }
        }
        qid++;
    }
    lcore_conf[0].type = LCORE_ROLE_MASTER;
    g_lcore_role[0] = LCORE_ROLE_MASTER;
    for (int i = 0; i < 8; i++) {
        hz_lcore_conf[i].id = i;
        hz_lcore_conf[i].type = LCORE_ROLE_FWD_WORKER;
//        hz_lcore_conf[i].in.id=1;
//        hz_lcore_conf[i].out.id=0;
//        hz_lcore_conf[i].in.rx.id=i;
//        hz_lcore_conf[i].in.rx.len=0;
        hz_lcore_conf[i].in = rte_malloc("hz_port_conf", sizeof(struct hz_port_conf), 0);
        hz_lcore_conf[i].in->rx = rte_malloc("hz_queue_conf", sizeof(struct hz_queue_conf), 0);
        hz_lcore_conf[i].in->id = 1;
        hz_lcore_conf[i].in->rx->len = 0;
        hz_lcore_conf[i].in->rx->id = i;
        hz_lcore_conf[i].in->tx = rte_malloc("hz_queue_conf", sizeof(struct hz_queue_conf), 0);
        hz_lcore_conf[i].in->id = 1;
        hz_lcore_conf[i].in->tx->len = 0;
        hz_lcore_conf[i].in->tx->id = i;
        for (int j = 0; j < 1024; j++) {
            hz_lcore_conf[i].in->rx->mbufs[j] = NULL;
            hz_lcore_conf[i].in->tx->mbufs[j] = NULL;
        }
    }

    for (int i = 0; i < LINK_LAYER_MAX_JOB; i++) {
        err = wlb_lcore_job_register(&link_layer_jobs[i].job, link_layer_jobs[i].role);
        assert(err >= 0);
    }

    for(int i=0;i<WLB_MAX_NIC_PORTS;i++){
        for(int j=0;j<WLB_MAX_ETH_TYPE;j++){
            hz_pkt_types[i][j]=NULL;
        }
    }
    return EWLB_OK;
}

int link_layer_term(void) {
    return EWLB_OK;
}
