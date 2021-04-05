#include <stdlib.h>
#include <stdio.h>

#include "lib.h"
#include "aspos_lwip.h"
#include "lwip/tcp.h"

#define MAX_READ 64

#define EXIT_STRING "exit\n"

int netcat_client(char* ip, uint16_t port)	{
	int sock, res;
	struct sockaddr_in server;
	char buf[MAX_READ+1];
	int len;

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = inet_addr(ip);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0)	{
		dprintf(STDERR, "socket() returned %i\n", sock);
		return sock;
	}

	int val = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(int));

	res = connect(sock, (struct sockaddr*)&server, sizeof(server));
	if(res < 0)	{
		dprintf(STDERR, "connect() returned %i\n", res);
		return res;
	}

	char c;
	printf("Connected and ready...\n");
	while(true)	{
		len = read(STDIN, buf, MAX_READ);
		/*
		* getc and putc misses keystrokes, so not usable yet
		len = 0;
		while((c = get_char(STDIN)) != '\n')	{
			buf[len++] = c;
			put_char(STDOUT, c);
		}
		put_char(STDOUT, '\n');
		*/
		buf[len] = 0x00;
		write(STDOUT, buf, len);

		if(strcmp(buf, EXIT_STRING) == 0)	break;

		res = send(sock, buf, len, 0);
		if(res < 0)	{
			dprintf(STDERR, "send() returned %i\n", res);
			continue;
		}
	}
	return OK;
}

int main(int argc, char* argv[])	{
	char* ip;
	long val;
	uint16_t port;
	int res;

	if(argc != 3)	{
		printf("Usage <program> <ip> <port>\n");
		exit(1);
	}

	ip = argv[1];
	val = strtol(argv[2], NULL, 0);
	if(val == LONG_MIN || val == LONG_MAX)	{
		printf("Port value '%s' could not be interpreted as a number\n", argv[2]);
		exit(1);
	}

	if(val < 0 || (val >= (1<<16)))	{
		printf("Port value '%i' is invalid\n", val);
		exit(1);
	}
	port = val;

	printf("Attempting to initialize network\n");
	res = network_init_dhcp(NET_INIT_DEFAULT_ROUTE | NET_INIT_START_DNS);
	if(res != OK)	{
		printf("Net init returned: %i\n", res);
		exit(1);
	}

	printf("Connected to network, starting client\n");
	netcat_client(ip, port);
	return 0;
}
