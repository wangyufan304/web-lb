#ifndef __WLB_SCHEDULE_H__
#define __WLB_SCHEDULE_H__

#include "list.h"
#include "dpdk.h"
#include "common.h"
#include "global_data.h"

typedef void (*job_fn)(void *arg);

struct wlb_lcore_job
{
  char name[32];
  void (*func)(void* arg);
  void *data;
  struct list_head list;
} __rte_cache_aligned;

struct wlb_lcore_job_array
{
  struct wlb_lcore_job job;
  wlb_cpu_lcore_role_t role;
}__rte_cache_aligned;

void
wlb_lcore_start(int master);
int wlb_scheduler_init(void);
int wlb_scheduler_term(void);
int wlb_lcore_job_register(struct wlb_lcore_job *lcore_job, wlb_cpu_lcore_role_t role);

#endif /*  __WLB_SCHEDULE_H__*/