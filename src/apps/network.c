#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "lib.h"
#include "aspos_lwip.h"

#include "lwip/api.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/dhcp.h"
#include "lwip/tcpip.h"
#include "lwip/etharp.h"
#include "lwip/sockets.h"

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

#define MAX_WAIT_TICKS 10

/* is in
* #include "netif/ethernet.h"
* But that is not included in image
*/
err_t ethernet_input(struct pbuf *p, struct netif *netif);


// Some test functions to check if it's working
void send_udp_packet(char* msg);
void send_udp_socket(char* msg);
void send_tcp_socket(char* msg);


int main(int argc, char* argv[])	{
	memcmp("asd", "qwe", 3);
	struct netif* n = (struct netif*)kmalloc( sizeof(struct netif) );
	err_t ret;
	int count;

	/* Start network interface without having an IP attached */
	if(netif_add_noaddr(n, NULL, aspos_netif_init, ethernet_input) == NULL)	{
		printf("netif_add returned NULL\n");
		return 1;
	}

	/* Check if interface is up */
	if(!netif_is_up(n))	{
		printf("Interface is not up\n");
		exit(1);
	}

	ret = dhcp_start(n);
	if(ret != ERR_OK)	{
		printf("dhcp_start() returned %i\n", ret);
		exit(1);
	}

	// Check if we have gotten an IP 
	count = 0;
	do {
		tsleep(2);
		count += 2;
	} while((!dhcp_supplied_address(n)) && (count < MAX_WAIT_TICKS));

	if(count > MAX_WAIT_TICKS)	{
		printf("No IP from DHCP\n");
		exit(1);

	}

	send_tcp_socket("Hello from Qemu\n");

	msleep(5000);
	exit(0);

	/*
	while(1)	{
		yield();
	}
	*/
	return 0;
}


void send_udp_packet(char* msg)	{
	struct udp_pcb* u;
	struct pbuf* p;
	struct ip4_addr to;
	int bytes = strlen(msg);
	int res;
	
	IP4_ADDR(&to, 192,168,0,20);

	printf("Sending %iB in udp packet\n", bytes);
	p = pbuf_alloc(PBUF_TRANSPORT, bytes, PBUF_POOL);
	if(p == NULL)	{
		printf("Unable to alloc pbuf\n");
		exit(1);
	}
	pbuf_take(p, msg, bytes);

	u = udp_new();
	udp_connect(u, &to, 5555);
	res = udp_send(u, p);
	if(res != ERR_OK)	{
		printf("Error in sending packet: %i\n", res);
	}
	msleep(3000);
	exit(1);
}

void send_udp_socket(char* msg)	{
	int sock, res;
	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr("192.168.0.20");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	server.sin_family = AF_INET;
	server.sin_port = htons(5555);

	if(sock < 0)	{
		printf("Unable to create socket\n");
		exit(1);
	}

	res = connect(sock, (struct sockaddr*)&server, sizeof(server));
	if(res < 0)	{
		printf("Cannot connect\n");
		exit(1);
	}

	res = send(sock, msg, strlen(msg), 0);
	printf("Sent %i bytes of data\n", res);
}

void send_tcp_socket(char* msg)	{
	int sock, res, msglen = strlen(msg);
	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr("192.168.0.20");
	char* buf;
	
	buf = (char*)kmalloc( msglen + 1 );
	if(buf == NULL)	exit(1);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	server.sin_family = AF_INET;
	server.sin_port = htons(5555);

	if(sock < 0)	{
		printf("Unable to create socket\n");
		exit(1);
	}

	res = connect(sock, (struct sockaddr*)&server, sizeof(server));
	if(res < 0)	{
		printf("Cannot connect\n");
		exit(1);
	}

	res = send(sock, msg, msglen, 0);
	printf("Sent %i bytes of data\n", res);

	res = recv(sock, (void*)buf, msglen, 0);
	if(res > 0)	{
		buf[res] = 0x00;
		printf("Received %i bytes: %s\n", res, buf);
	}
	else	{
		printf("no response, returned: %i\n", res);
	}

	close(sock);
}

