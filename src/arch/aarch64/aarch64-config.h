#ifndef __AARCH64_CONFIG_H
#define __AARCH64_CONFIG_H



#ifndef ARM64_PAGE_SIZE
# define ARM64_PAGE_SIZE 4096
#endif


#define ARM64_VA_BITS CONFIG_AARCH64_VA_BITS


/* Some sanity checking code on defined values */

/*
#if ARM64_VA_BITS != 48
#error "Supplied value for VA_BITS is not supported"
#endif
*/

#if ARM64_PAGE_SIZE != 4096
#error "Supplied value for page size is not supported"
#endif

#endif
