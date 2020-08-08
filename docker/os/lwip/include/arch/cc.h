#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#define LWIP_NO_CTYPE_H    0
#define LWIP_NO_STDDEF_H   0
#define LWIP_NO_INTTYPES_H 0
#define LWIP_NO_LIMITS_H   0
#define LWIP_NO_STDDEF_H   0
#define LWIP_NO_STDINT_H   0

#define LWIP_PLATFORM_ASSERT while(1)

// Already defined by compiler
//#define BYTE_ORDER  LITTLE_ENDIAN

#define SSIZE_MAX INT_MAX
#define LWIP_TIMEVAL_PRIVATE 0
#define LWIP_ERRNO_STDINCLUDE	1

typedef unsigned int sys_prot_t;

#endif
