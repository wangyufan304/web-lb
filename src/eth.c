//
// Created by root on 1/9/25.
//
#include "eth.h"

static struct list_head pkt_types;

static const eth_protocol_map_t eth_protocol_map[] = {
        {RTE_ETHER_TYPE_IPV4,            "IPv4 Protocol"},
        {RTE_ETHER_TYPE_IPV6,            "IPv6 Protocol"},
        {RTE_ETHER_TYPE_ARP,             "ARP Protocol"},
        {RTE_ETHER_TYPE_RARP,            "Reverse ARP Protocol"},
        {RTE_ETHER_TYPE_VLAN,            "IEEE 802.1Q VLAN tagging"},
        {RTE_ETHER_TYPE_QINQ,            "IEEE 802.1ad QinQ tagging"},
        {RTE_ETHER_TYPE_QINQ1,           "Deprecated QinQ VLAN"},
        {RTE_ETHER_TYPE_QINQ2,           "Deprecated QinQ VLAN"},
        {RTE_ETHER_TYPE_QINQ3,           "Deprecated QinQ VLAN"},
        {RTE_ETHER_TYPE_PPPOE_DISCOVERY, "PPPoE Discovery Stage"},
        {RTE_ETHER_TYPE_PPPOE_SESSION,   "PPPoE Session Stage"},
        {RTE_ETHER_TYPE_ETAG,            "IEEE 802.1BR E-Tag"},
        {RTE_ETHER_TYPE_1588,            "IEEE 802.1AS 1588 Precise Time Protocol"},
        {RTE_ETHER_TYPE_SLOW,            "Slow Protocols (LACP and Marker)"},
        {RTE_ETHER_TYPE_TEB,             "Transparent Ethernet Bridging"},
        {RTE_ETHER_TYPE_LLDP,            "LLDP Protocol"},
        {RTE_ETHER_TYPE_MPLS,            "MPLS Ethertype"},
        {RTE_ETHER_TYPE_MPLSM,           "MPLS Multicast Ethertype"},
        {RTE_ETHER_TYPE_ECPRI,           "eCPRI Ethertype"}
};

void print_eth_protocol(uint16_t eth_type) {
    for (size_t i = 0; i < sizeof(eth_protocol_map) / sizeof(eth_protocol_map_t); i++) {
        if (eth_protocol_map[i].eth_type == eth_type) {
            printf("%s\n", eth_protocol_map[i].protocol_name);
            return;
        }
    }
    printf("Unknown Ethertype (0x%04X)\n", eth_type);  // 未知类型
}

struct pkt_type *pkt_type_get(__be16 type, struct nic_port *port) {
    struct pkt_type * pkt;
    list_for_each_entry(pkt,&pkt_types,list){
        if(pkt->type == type){}
        return  pkt;
    }
    return NULL;

}

void pkt_type_register(struct pkt_type *pkt) {
    list_add(&pkt->list,&pkt_types);
}

static void init_pkt_array(void) {
    INIT_LIST_HEAD(&pkt_types);
}

void init_eth(void) {
    init_pkt_array();
}