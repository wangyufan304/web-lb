//
// Created by root on 1/6/25.
//

#include "nic.h"

struct  nic_port *hz_nic_ports[WLB_MAX_NIC_PORTS];

enum {
    NIC_PORT_FLAG_ENABLED                 = (0x1<<0),
    NIC_PORT_FLAG_RUNNING                 = (0x1<<1),
    NIC_PORT_FLAG_STOPPED                 = (0x1<<2),
    NIC_PORT_FLAG_RX_IP_CSUM_OFFLOAD      = (0x1<<3),
    NIC_PORT_FLAG_TX_IP_CSUM_OFFLOAD      = (0x1<<4),
    NIC_PORT_FLAG_TX_TCP_CSUM_OFFLOAD     = (0x1<<5),
    NIC_PORT_FLAG_TX_UDP_CSUM_OFFLOAD     = (0x1<<6),
    NIC_PORT_FLAG_TX_VLAN_INSERT_OFFLOAD  = (0x1<<7),
    NIC_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD   = (0x1<<8),
    NIC_PORT_FLAG_FORWARD2KNI             = (0x1<<9),
    NIC_PORT_FLAG_TC_EGRESS               = (0x1<<10),
    NIC_PORT_FLAG_TC_INGRESS              = (0x1<<11),
    NIC_PORT_FLAG_NO_ARP                  = (0x1<<12),
};

/* check and adapt device offloading/rss features */
static void adapt_device_conf(portid_t port_id, uint64_t *rss_hf,
                              uint64_t *rx_offload, uint64_t *tx_offload)
{
    struct rte_eth_dev_info dev_info;

    rte_eth_dev_info_get(port_id, &dev_info);

    if ((dev_info.flow_type_rss_offloads | *rss_hf) !=
        dev_info.flow_type_rss_offloads) {
        rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_PORT, "NETIF" ": " "Ethdev port_id=%u invalid rss_hf: 0x%""l" "x"", valid value: 0x%""l" "x""\n", port_id, *rss_hf, dev_info.flow_type_rss_offloads);
        /* mask the unsupported rss_hf */
        *rss_hf &= dev_info.flow_type_rss_offloads;
    }

    if ((dev_info.rx_offload_capa | *rx_offload) != dev_info.rx_offload_capa) {
        rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_PORT, "NETIF" ": " "Ethdev port_id=%u invalid rx_offload: 0x%""l" "x"", valid value: 0x%""l" "x""\n", port_id, *rx_offload, dev_info.rx_offload_capa);
        /* mask the unsupported rx_offload */
        *rx_offload &= dev_info.rx_offload_capa;
    }

    if ((dev_info.tx_offload_capa | *tx_offload) != dev_info.tx_offload_capa) {
        rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_PORT, "NETIF" ": " "Ethdev port_id=%u invalid tx_offload: 0x%""l" "x"", valid value: 0x%""l" "x""\n", port_id, *tx_offload, dev_info.tx_offload_capa);
        /* mask the unsupported tx_offload */
        *tx_offload &= dev_info.tx_offload_capa;
    }
}

extern struct rte_mempool *hzpktmbuf_pool[WLB_MAX_SOCKET];
static struct rte_eth_conf port_default_conf = {
        .rxmode = {.mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        .offloads = DEV_RX_OFFLOAD_CHECKSUM,
        }, // 启用 RSS 模式
        .rx_adv_conf.rss_conf = {
                .rss_key = NULL, // 使用默认 RSS key
                .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP, // 配置 RSS 支持的协议
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
        },

};
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define	ETHER_CRC_LEN	4                        /* bytes in CRC field */
#define	ETHER_MAX_LEN	(ETH_FRAME_LEN + ETHER_CRC_LEN) /* max packet length */
static struct rte_eth_conf default_port_conf = {
        .rxmode = {
                .mq_mode        = ETH_MQ_RX_RSS,
                .max_rx_pkt_len = ETHER_MAX_LEN,
                .split_hdr_size = 0,
                .offloads = DEV_RX_OFFLOAD_IPV4_CKSUM,
        },
        .rx_adv_conf = {
                .rss_conf = {
                        .rss_key = NULL,
                        .rss_hf  = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
                },
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
        },
};

static inline void setup_dev_of_flags(struct nic_port *port)
{
    port->flag |= NIC_PORT_FLAG_ENABLED;

    /* tx offload conf and flags */
    if (port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)
        port->flag |= NIC_PORT_FLAG_TX_IP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)
        port->flag |= NIC_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)
        port->flag |= NIC_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;


    if (strncmp(port->dev_info.driver_name, "net_virtio", strlen("net_virtio")) == 0) {
        port->flag |= NIC_PORT_FLAG_TX_IP_CSUM_OFFLOAD;
        port->flag &= ~NIC_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;
        port->flag &= ~NIC_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;
    }
    /* rx offload conf and flags */
    if (port->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
        port->flag |= NIC_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD;
        port->dev_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
    }
    if (port->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM)
        port->flag |= NIC_PORT_FLAG_RX_IP_CSUM_OFFLOAD;
}


static struct nic_port *
nic_port_alloc(portid_t pid, int nrxq, int ntxq, const struct  rte_eth_conf *conf)
{
    int i;
    struct nic_port *port;
    port = rte_zmalloc("port",sizeof(struct nic_port),RTE_CACHE_LINE_SIZE);
    if(!port){
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PORT, "NETIF" ": " "%s: no memory\n", __func__);
        return NULL;
    }
    port->pid =pid;
    snprintf(port->nic_name,sizeof(port->nic_name),"dpdk%d",pid);
    port->nrx_queue = nrxq;
    port->ntx_queue = ntxq;
    port->socket_id = rte_eth_dev_socket_id(pid);
    port->mbuf_pool = hzpktmbuf_pool[port->socket_id];
    rte_eth_macaddr_get((uint8_t)pid,&port->addr);
    rte_eth_dev_get_mtu((uint8_t)pid,&port->mtu);
    rte_eth_dev_info_get((uint8_t)pid,&port->dev_info);
    port->dev_conf = *conf;
    port->flag |= NIC_PORT_FLAG_ENABLED;
    setup_dev_of_flags(port);
    return port;

}

int nic_port_start(struct nic_port *port)
{
    int ret;
    queueid_t qid;
    struct rte_eth_txconf txconf;
    if((ret = rte_eth_dev_set_mtu(port->pid,port->mtu)!=EWLB_OK))
        return ret;
    port->flag =377;
    if (port->flag & NIC_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
    if (port->flag & NIC_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
    if (port->flag & NIC_PORT_FLAG_TX_TCP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
    port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    adapt_device_conf(port->pid, &port->dev_conf.rx_adv_conf.rss_conf.rss_hf,
                      &port->dev_conf.rxmode.offloads, &port->dev_conf.txmode.offloads);
    port->nrx_queue = 8;
    port->ntx_queue = 8;
    ret = rte_eth_dev_configure(port->pid, port->nrx_queue, port->ntx_queue, &port->dev_conf);
    if (ret < 0 ) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PORT, "NETIF" ": " "%s: fail to config %s\n", __func__, port->nic_name);
        return EWLB_INVAL;
    }
    for (qid = 0; qid < port->nrx_queue; qid++) {
        ret = rte_eth_rx_queue_setup(port->pid, qid, 1024,
                                     port->socket_id, NULL, hzpktmbuf_pool[port->socket_id]);
        if (ret < 0) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PORT, "NETIF" ": " "%s: fail to config %s:rx-queue-%d\n", __func__,
                    port->nic_name, qid);
            return EWLB_INVAL;
        }
    }// setup tx queues
    for (qid = 0; qid < port->ntx_queue; qid++) {
        memcpy(&txconf, &port->dev_info.default_txconf, sizeof(struct rte_eth_txconf));
        txconf.offloads = port->dev_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(port->pid, qid, 512, port->socket_id, &txconf);
        if (ret < 0) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PORT, "NETIF" ": " "%s: fail to config %s:tx-queue-%d\n", __func__,
                    port->nic_name, qid);
            return EWLB_INVAL;
        }
    }
    ret = rte_eth_dev_start(port->pid);
    if (ret < 0) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PORT, "NETIF" ": " "%s: fail to start %s\n", __func__, port->nic_name);
        return EWLB_INVAL;
    }
}

int nic_port_init(void) {
    int nports;
    portid_t pid;
    struct nic_port *port;
    struct rte_eth_conf this_eth_conf;
    nports = rte_eth_dev_count_avail();
    if (nports <= 0)
        rte_exit(EXIT_FAILURE, "No dpdk ports found!\n"
                               "Possibly nic or driver is not dpdk-compatible.\n");
    this_eth_conf = default_port_conf;
    for(pid = 0; pid<nports;pid++){
        port = nic_port_alloc(pid,8,8,&this_eth_conf);
        hz_nic_ports[pid] = port;
        if(!port){
            rte_exit(EXIT_FAILURE, "Port allocate fail, exiting...\n");
        }
    }
    return EWLB_OK;
}
struct nic_port* get_nic_ports(portid_t pid)
{
    return hz_nic_ports[pid];
}
int nic_port_term(void)
{
    return EWLB_OK;
}