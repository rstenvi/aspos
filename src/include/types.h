#ifndef __TYPES_H
#define __TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;


typedef uint16_t tid_t;
typedef uint64_t ptr_t;
typedef uint16_t uid_t;
typedef uint16_t gid_t;
typedef volatile uint8_t mutex_t;
typedef uint64_t sysfilter_t;
typedef uint32_t ipv4_t;


typedef int (*kputc_t)(char);
typedef int (*kgetc_t)(void);
typedef int (*kputs_t)(const char*);
typedef int (*kputc_t)(char);
typedef int (*printf_t)(const char*, ...);

#define __force_inline __attribute__((always_inline))
#define __noreturn __attribute__((noreturn))


/*
* These are used to create unique identifiers in the code, which is used to
* create variables w/o having to define a name.
*/
#define __UNIQUE_ID(prefix,line) prefix##line
#define _UNIQUE_ID(prefix,line) __UNIQUE_ID(prefix,line)



#endif
