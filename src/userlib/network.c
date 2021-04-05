/**
* Reasonable configurations of network.
*/

#include "lib.h"
#include "lwip/api.h"
#include "lwip/dhcp.h"
//#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "aspos_lwip.h"

#define MAX_WAIT_TICKS 30

int network_init_dhcp(long flags)	{
	struct netif* n = (struct netif*)malloc( sizeof(struct netif) );
	int count, ret;

	/* Start network interface without having an IP attached */
	if(netif_add_noaddr(n, NULL, aspos_netif_init, ethernet_input) == NULL)	{
		printf("netif_add returned NULL\n");
		return -(GENERAL_FAULT);
	}

	/* Check if interface is up */
	if(!netif_is_up(n))	{
		printf("Interface is not up\n");
		return -(GENERAL_FAULT);
	}

	ret = dhcp_start(n);
	if(ret != ERR_OK)	{
		printf("dhcp_start() returned %i\n", ret);
		return -(GENERAL_FAULT);
	}
	
	// Check if we have gotten an IP 
	count = 0;
	do {
		tsleep(2);
		count += 2;
	} while((!dhcp_supplied_address(n)) && (count < MAX_WAIT_TICKS));

	if(count >= MAX_WAIT_TICKS)	{
		printf("No IP from DHCP\n");
		return -(GENERAL_FAULT);
	}

	if(FLAG_SET(flags, NET_INIT_DEFAULT_ROUTE))	{
		netif_set_default(n);
	}

	if(FLAG_SET(flags, NET_INIT_START_DNS))	{
		dns_init();

		/*
		ip_addr_t* q = dns_getserver(0);
		ip_addr_t res;
		netconn_gethostbyname("example.com", &res);

		// Had problems using the socket version
//		struct hostent* h = gethostbyname("example.com");
		*/
	}

	return OK;
}

