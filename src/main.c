#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <rte_eal.h>
#include "link_layer.h"
#include "tools.h"
#include "global_data.h"
#include "common.h"
#include "pidfile.h"
#include "schedule.h"
#include "nic.h"

#define WLB_MODULES                                      \
{                                                        \
    WLB_MODULE(MODULE_SCHEDULER,    "wlb scheduler",     wlb_scheduler_init, wlb_scheduler_term), \
    WLB_MODULE(MODULE_LINK_LAYER,   "wlb link layer",    link_layer_init,    link_layer_term), \
    WLB_MODULE(MODULE_NIC_PORT_LAYER,   "nic port init",    nic_port_init,    nic_port_term), \
    WLB_MODULE(MODULE_LAST,         "last",              NULL,               NULL)                 \
}


#define WLB_MODULE(a, b, c, d) a
enum wlb_modules WLB_MODULES;
#undef WLB_MODULE

#define WLB_MODULE(a, b, c, d) b
static const char *wlb_modules[] = WLB_MODULES;
#undef WLB_MODULE

typedef int (*wlb_module_init_pt)(void);

typedef int (*wlb_module_term_pt)(void);

#define WLB_MODULE(a, b, c, d) c
wlb_module_init_pt wlb_module_inits[] = WLB_MODULES;
#undef WLB_MODULE

#define WLB_MODULE(a, b, c, d) d
wlb_module_term_pt wlb_module_terms[] = WLB_MODULES;
#undef WLB_MODULE

static int set_all_thread_affinity(void) {
    int s;
    lcoreid_t cid;
    pthread_t tid;
    cpu_set_t cpuset;
    unsigned long long cpumask = 0;

    tid = pthread_self();
    CPU_ZERO(&cpuset);
    for (cid = 0; cid < RTE_MAX_LCORE; cid++)
        CPU_SET(cid, &cpuset);

    s = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        errno = s;
        perror("fail to set thread affinty");
        return -1;
    }

    CPU_ZERO(&cpuset);
    s = pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        errno = s;
        perror("fail to get thread affinity");
        return -2;
    }

    for (cid = 0; cid < RTE_MAX_LCORE; cid++) {
        if (CPU_ISSET(cid, &cpuset))
            cpumask |= (1LL << cid);
    }
    printf("current thread affinity is set to %llX\n", cpumask);

    return 0;
}

static void modules_init(void) {
    int m, err;
    for (m = 0; m <= MODULE_LAST; m++) {
        if (wlb_module_inits[m]) {
            if ((err = wlb_module_inits[m]()) != EWLB_OK) {
                rte_exit(EXIT_FAILURE, "Failed to init %s\n", wlb_modules[m]);
            }else{
                fprintf(stdout, "%s init successfully.\n",wlb_modules[m]);
            }
        }
    }
}

static void modules_term(void) {
    int m, err;

    for (m = MODULE_LAST; m >= 0; m--) {
        if (wlb_module_terms[m]) {
            if ((err = wlb_module_terms[m]()) != EWLB_OK) {
                rte_exit(EXIT_FAILURE, "failed to term %s\n",
                         wlb_modules[m]);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    unsigned lcore_id;
    int nports;
    int err;
    struct nic_port *dev;
    portid_t pid;
    if (wlb_running(wlb_pid_file)) {
        fprintf(stderr, "wlb is already running\n");
        exit(EXIT_FAILURE);
    }
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }
    printf("numa_nodes:%d\n", get_numa_nodes());

    modules_init();
    if (set_all_thread_affinity() != 0) {
        fprintf(stderr, "set_all_thread_affinity failed\n");
        exit(EXIT_FAILURE);
    }else{
        fprintf(stdout, "set_all_thread_affinity success\n");
    }
    nports = rte_eth_dev_count_avail();
    for(pid = 0;pid<nports;pid++){
        dev = get_nic_ports(pid);
        if(dev == NULL){
            continue;
        }
        err = nic_port_start(dev);
        if(err!=EWLB_OK){
            printf("START ERROR %s\n",dev->nic_name);
        }
    }
    printf("port init successfully!\n");
    wlb_lcore_start(1);
    wlb_lcore_start(0);
}
