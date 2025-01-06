#ifndef __WLB_GLOBAL_DATA_H__
#define __WLB_GLOBAL_DATA_H__

#include <rte_per_lcore.h>
#include "common.h"

typedef enum wlb_cpu_lcore_role_type
{
  LCORE_ROLE_NO_USED,
  LCORE_ROLE_IDLE,
  LCORE_ROLE_MASTER,
  LCORE_ROLE_FWD_WORKER,
  LCORE_ROLE_MAX,
} wlb_cpu_lcore_role_t;

extern char *wlb_pid_file;
extern char *wlb_ipc_file;
extern char *wlb_conf_file;
extern wlb_cpu_lcore_role_t g_lcore_role[WLB_MAX_LCORE];

#endif /* __WLB_GLOBAL_DATA_H__ */
