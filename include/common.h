#ifndef __WLB_COMMON_H__
#define __WLB_COMMON_H__

#include <bits/stdint-uintn.h>
#include "debug.h"
#define WLB_MAX_SOCKET 2

#define NIC_MAX_PKT_BURST 32

#define NIC_MAX_QUEUES 32

#define NIC_MAX_RTE_PORT 16

#define WLB_MAX_LCORE 64

#define  WLB_NIC_MAX_NAME 32

#define  WLB_MAX_NIC_PORTS 10

#define WLB_MAX_ETH_TYPE 20
#ifndef lcoreid_t
typedef uint8_t lcoreid_t;
#endif

#ifndef portid_t
typedef uint8_t portid_t;
#endif

#ifndef queueid_t
typedef uint8_t queueid_t;
#endif

enum
{
  EWLB_OK = 0,
  EWLB_EXIST = -1,
  EWLB_RETURN = -2,
  EWLB_INVAL = -3,
  EWLB_DROP = -4,
};

#endif /* __WLB_COMMON_H__*/
