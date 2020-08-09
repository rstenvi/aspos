#ifndef __ASPOS_LWIP_H
#define __ASPOS_LWIP_H

#include "lwip/api.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"

#define ETH_DRIVER "/ethernet"


/*
* lwip/sockets.h creates macros for some of the function names we use in our
* regular syscalls. If any of these are needed, the function name prefixed with
* "lwip_" should be used instead.
*/
#undef read
#undef close
#undef fcntl
#undef ioctl
#undef write


/* is in
* #include "netif/ethernet.h"
* But that is not included in image
*/
err_t ethernet_input(struct pbuf *p, struct netif *netif);


struct aspos_ethif {
	int fd;
};

// ------------------------ lwip_netif.c ------------------------- //
err_t aspos_netif_link_output(struct netif *netif, struct pbuf *p);
void tcp_thread(void* arg);
err_t aspos_netif_init(struct netif* netif);
void aspos_netif_read_loop(void* arg);



// ------------------------ network.c ------------------------------ //
#define NET_INIT_DEFAULT_ROUTE (1 << 0)
int network_init_dhcp(long flags);

#endif
