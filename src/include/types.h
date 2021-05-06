#ifndef __TYPES_H
#define __TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



typedef uint16_t tid_t;
typedef uint64_t ptr_t;

typedef uint16_t uid_t;
typedef uint16_t gid_t;

typedef volatile uint8_t mutex_t;

typedef uint64_t sysfilter_t;

#define __force_inline __attribute__((always_inline))

#endif
