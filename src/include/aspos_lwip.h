#ifndef __ASPOS_LWIP_H
#define __ASPOS_LWIP_H

#include "lwip/api.h"
#include "lwip/sys.h"

#define ETH_DRIVER "/ethernet"

struct aspos_ethif {
	int fd;
};

// ------------------------ lwip_netif.c ------------------------- //
err_t aspos_netif_link_output(struct netif *netif, struct pbuf *p);
void tcp_thread(void* arg);
err_t aspos_netif_init(struct netif* netif);
void aspos_netif_read_loop(void* arg);


#endif
