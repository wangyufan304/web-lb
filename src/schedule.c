#include "schedule.h"
#include "common.h"
#include "global_data.h"
#include "dpdk.h"
#include "list.h"

static struct list_head wlb_lcore_jobs[LCORE_ROLE_MAX];


static inline void
do_lcore_job(struct wlb_lcore_job *job){
    if(job)
        job->func(job->data);
}
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

static int
wlb_job_loop(__rte_unused void *argv) {
    struct wlb_lcore_job *job;
    lcoreid_t cid = rte_lcore_id();
    wlb_cpu_lcore_role_t role = g_lcore_role[cid];

    if (role == LCORE_ROLE_NO_USED || role == LCORE_ROLE_MAX) {
        return EWLB_RETURN;
    }
    while (1) {
        /* code */
        list_for_each_entry(job,&wlb_lcore_jobs[role],list){
            do_lcore_job(job);
        }
    }
    return EWLB_OK;
}

int wlb_lcore_job_register(struct wlb_lcore_job *lcore_job, wlb_cpu_lcore_role_t role) {
    struct wlb_lcore_job *cur;
    if(unlikely(NULL==lcore_job)||role>=LCORE_ROLE_MAX){
        return EWLB_INVAL;
    }
    list_for_each_entry(cur, &wlb_lcore_jobs[role], list) {
        if (cur == lcore_job) {
            return EWLB_EXIST;
        }
    }
    list_add_tail(&lcore_job->list, &wlb_lcore_jobs[role]);
    return EWLB_OK;
}

void wlb_lcore_start(int master) {
    if (master) {
        rte_eal_mp_remote_launch(wlb_job_loop, NULL, CALL_MAIN);
        return;
    }
    rte_eal_mp_remote_launch(wlb_job_loop, NULL, SKIP_MAIN);
}

int wlb_scheduler_init(void) {
    int i;
    for (i = 0; i < LCORE_ROLE_MAX; i++) {
        INIT_LIST_HEAD(&wlb_lcore_jobs[i]);
    }
    return EWLB_OK;
}

int wlb_scheduler_term(void) {
    return EWLB_OK;
}