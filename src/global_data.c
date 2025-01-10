#include "global_data.h"
char *wlb_pid_file;
char *wlb_ipc_file;
char *wlb_conf_file;
wlb_cpu_lcore_role_t g_lcore_role[WLB_MAX_LCORE]={
        LCORE_ROLE_NO_USED
};
struct list_head wlb_core_arp_table[HZ_USE_MAX_CORE];