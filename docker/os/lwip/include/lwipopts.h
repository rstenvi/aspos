#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H


#define NO_SYS 0

#define MEM_ALIGNMENT 8U

#define MEM_SIZE 4096

#define LWIP_COMPAT_MUTEX_ALLOWED 1
#define LWIP_COMPAT_MUTEX 1

/* These three are needed for DHCP */
#define LWIP_ARP 1
#define LWIP_ACD 1
#define LWIP_DHCP 1

/* I had problems with this */
#define LWIP_DHCP_DOES_ACD_CHECK 0

/*
* lwIP memory pool is faster, but did not work out of the box
*/
#define MEM_LIBC_MALLOC 1


#define LWIP_NETCONN 1

#define LWIP_TCP 1
#define LWIP_ICMP 0
#define LWIP_RAW 0
#define LWIP_AUTOIP 0
#define LWIP_SNMP 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_UDP 1
#define LWIP_SOCKET 1
#define LWIP_STATS 0
#define PPP_SUPPORT 0

#define LWIP_TCPIP_CORE_LOCKING 1


#define IP_FORWARD 0
#define IP_OPTIONS_ALLOWED 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0


// Should be enabled eventually

#define LWIP_TIMERS 0
#define SYS_LIGHTWEIGHT_PROT            0

#endif
