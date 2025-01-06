#include "tools.h"

int get_numa_nodes(void)
{
  int numa_nodes;

  if (numa_available() < 0)
    numa_nodes = 0;
  else
    numa_nodes = numa_max_node();

  return (numa_nodes + 1);
}
