#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "common.h"
#include "schedule.h"
#include "link_layer.h"
#include "tools.h"

#define LINK_LAYER_PKTPOOL_NB_MBUF_DEF 65535
#define LINK_LAYER_PKTPOOL_MBUF_CACHE_DEF 256

int link_layer_pktpool_nb_mbuf = LINK_LAYER_PKTPOOL_NB_MBUF_DEF;
int link_layer_pktpool_mbuf_cache = LINK_LAYER_PKTPOOL_MBUF_CACHE_DEF;

struct rte_mempool *hzpktmbuf_pool[WLB_MAX_SOCKET];
static struct cpu_lcore_conf lcore_conf[WLB_MAX_LCORE + 1];
static struct hz_lcore_conf hz_lcore_conf[8];

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

void link_layer_init_port(portid_t pid, int nrx, int ntx) {
    // 获取可用的以太网设备数量
    uint16_t nb_sys_ports = rte_eth_dev_count_avail(); //
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }
    assert(pid<nb_sys_ports);

    // 检索以太网设备的上下文信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(pid, &dev_info); //
    printf("%d port: rx-%d,tx_%d",pid,dev_info.max_rx_queues,dev_info.max_tx_queues);
    struct rte_eth_conf port_conf = {
            .rxmode = { .mq_mode = ETH_MQ_RX_RSS }, // 启用 RSS 模式
            .rx_adv_conf.rss_conf = {
                    .rss_key = NULL, // 使用默认 RSS key
                    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP, // 配置 RSS 支持的协议
            }
    };

    struct rte_eth_rxconf rx_conf = {

    };
    rte_eth_dev_configure(pid, nrx, ntx, &port_conf);

    //分配并设置以太网设备的接收队列。
    for (int i = 0; i < nrx; i++) {
        if (rte_eth_rx_queue_setup(pid, i, 1024,
                                   rte_eth_dev_socket_id(pid), NULL, hzpktmbuf_pool[rte_eth_dev_socket_id(pid)]) < 0) {

            rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
        }
    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(pid, 0, 1024,
                               rte_eth_dev_socket_id(pid), &txq_conf) < 0) {

        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");

    }
    //启动以太网设备
    if (rte_eth_dev_start(pid) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }


}


static inline uint16_t link_layer_rx_burst(portid_t pid, struct hz_queue_conf *qconf) {

    int nrx = 0;
    nrx = rte_eth_rx_burst(pid, rte_lcore_id(), qconf->mbufs, 1024);
    qconf->len = nrx;
//    printf("(%d-%d-%d)\t",rte_lcore_id(),qconf->id,nrx);
    return nrx;
}

static void lcore_process_packets(struct rte_mbuf **mbufs, lcoreid_t cid, uint16_t count) {

    for (int i = 0; i < count; i++) {
        struct rte_mbuf *mbuf = mbufs[i];
        struct rte_ether_hdr *eth_hdr;
        eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
        print_ether_addr(&eth_hdr->s_addr);
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
        hz_lcore_conf[cid].in->rx->len=link_layer_rx_burst(pid, hz_lcore_conf[cid].in->rx);
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
                    assert(lcore_conf[i].pqs[j].rx_queues[jj].mbufs[jjj]!=NULL);
                }
            }
            for (int jj = 0; jj < lcore_conf[i].pqs[j].ntx_queue; jj++) {
                for (int jjj = 0; jjj < NIC_MAX_PKT_BURST; jjj++) {
                    lcore_conf[i].pqs[j].tx_queues[jj].mbufs[jjj] = rte_pktmbuf_alloc(hzpktmbuf_pool[0]);
                    assert(lcore_conf[i].pqs[j].tx_queues[jj].mbufs[jjj]!=NULL);
                }
            }
        }
        qid++;
    }
    lcore_conf[0].type = LCORE_ROLE_MASTER;
    g_lcore_role[0] = LCORE_ROLE_MASTER;
    for(int i=0;i<8;i++){
        hz_lcore_conf[i].id=i;
        hz_lcore_conf[i].type = LCORE_ROLE_FWD_WORKER;
//        hz_lcore_conf[i].in.id=1;
//        hz_lcore_conf[i].out.id=0;
//        hz_lcore_conf[i].in.rx.id=i;
//        hz_lcore_conf[i].in.rx.len=0;
        hz_lcore_conf[i].in = rte_malloc("hz_port_conf",sizeof(struct hz_port_conf),0);
        hz_lcore_conf[i].in->rx = rte_malloc("hz_queue_conf",sizeof(struct hz_queue_conf),0);
        hz_lcore_conf[i].in->id=1;
        hz_lcore_conf[i].in->rx->len=0;
        hz_lcore_conf[i].in->rx->id=i;
        for(int j = 0;j<1024;j++){
            hz_lcore_conf[i].in->rx->mbufs[j]=NULL;
        }
    }

    for (int i = 0; i < LINK_LAYER_MAX_JOB; i++) {
        err = wlb_lcore_job_register(&link_layer_jobs[i].job, link_layer_jobs[i].role);
        assert(err >= 0);
    }




    return EWLB_OK;
}

int link_layer_term(void) {
    return EWLB_OK;
}
