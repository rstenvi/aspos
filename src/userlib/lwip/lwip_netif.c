#include <stdint.h>
#include <fcntl.h>

#include "lib.h"
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/etharp.h"

#include "aspos_lwip.h"




void tcp_thread(void* arg)	{
#if LWIP_TCPIP_CORE_LOCKING
	UNLOCK_TCPIP_CORE();
#endif
	new_thread( (uint64_t)aspos_netif_read_loop, 1, arg);
}


err_t aspos_netif_init(struct netif* netif)	{
	netif->output = etharp_output;
	netif->linkoutput = aspos_netif_link_output;
	netif->name[0] = 'e';
	netif->name[1] = 'n';

	netif->hwaddr_len = 6;

	// TODO: Should read this from driver
	memcpy(netif->hwaddr, "\x52\x54\x00\x12\x34\x56", 6);


	netif->flags |= NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_BROADCAST;

	// This should be appropriate for ethernet
	netif->mtu = 1500;

	// can use netif->state to store arbitrary data
	struct aspos_ethif* state = (struct aspos_ethif*)kmalloc( sizeof(struct aspos_ethif) );
	if(state == NULL)	exit(1);
	state->fd = open(ETH_DRIVER, 0, 0);
	if(state->fd < 0)	exit(1);
	netif->state = (void*)state;

	tcpip_init(tcp_thread, netif);

	netif_set_up(netif);
	netif_set_link_up(netif);


	return ERR_OK;
}


err_t aspos_netif_link_output(struct netif *netif, struct pbuf *p)	{
	struct aspos_ethif* state = (struct aspos_ethif*)(netif->state);

	int res = write(state->fd, p->payload, p->tot_len);
	if(res != p->tot_len)	{
		printf("surprising result from read: %i\n", res);
	}
	return ERR_OK;
}


void aspos_netif_read_loop(void* arg)	{
	char* buf = kmalloc( 1500 );
	int bytes = 0;
	struct netif* n = (struct netif*)arg;
	struct aspos_ethif* ethif = (struct aspos_ethif*)n->state;
	struct pbuf* p = NULL;

	while(1)	{
		bytes = read(ethif->fd, buf, 1500);
		if(bytes > 0)	{
			p = pbuf_alloc(PBUF_RAW, bytes, PBUF_POOL);
			if(p == NULL)	{
				printf("Unable to alloc pbuf\n");
				exit(1);
			}
			pbuf_take(p, buf, bytes);
			n->input(p, n);
		}
	}
}

