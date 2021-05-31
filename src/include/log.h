#ifndef __LOG_H
#define __LOG_H

#if !defined(UMODE)
#include "kernel.h"
#endif

#include <stdarg.h>

#ifndef CONFIG_LOG_LEVEL
# define CONFIG_LOG_LEVEL 0
#endif

extern struct os_data osdata;

/**
* All logging info is eventually sent to klog. This macro prints some extra info
* and then calls :c:func:`printk` for the remaining parameters.
*
* You should not call this directly, you should instead call one of:
*
* 1. :c:macro:`logd`
* 2. :c:macro:`logi`
* 3. :c:macro:`logw`
* 4. :c:macro:`loge`
* 5. :c:macro:`fatal`
*/
#define kwrite(s) puts(s)
#define kprintf(fmt, ...) osdata.printk(fmt, ##__VA_ARGS__)
#if defined(UMODE)
#define klog(fmt,...) dprintf(2, fmt, ##__VA_ARGS__)
#else
# if defined(CONFIG_SIMPLE_LOG_FORMAT)
void klog(char* fmt, ...);
# else
void klog(const char* lvl, const char* file, const char* func, char* fmt, ...);
# endif
#endif

#if CONFIG_LOG_LEVEL==0
# if defined(CONFIG_SIMPLE_LOG_FORMAT)
	#define logd(fmt, ...) klog(fmt, ##__VA_ARGS__)
# else
	#define logd(fmt, ...) klog("debug", __FILE__, __func__, fmt, ##__VA_ARGS__)
# endif
#else
	#define logd(fmt, ...)
#endif

#if CONFIG_LOG_LEVEL<=1
# if defined(CONFIG_SIMPLE_LOG_FORMAT)
	#define logi(fmt, ...) klog(fmt, ##__VA_ARGS__)
# else
	#define logi(fmt, ...) klog("info ", __FILE__, __func__, fmt, ##__VA_ARGS__)
# endif
#else
	#define logi(fmt, ...)
#endif

#if CONFIG_LOG_LEVEL<=2
# if defined(CONFIG_SIMPLE_LOG_FORMAT)
	#define logw(fmt, ...) klog(fmt, ##__VA_ARGS__)
# else
	#define logw(fmt, ...) klog("warn ", __FILE__, __func__, fmt, ##__VA_ARGS__)
# endif
#else
	#define logw(fmt, ...)
#endif

#if CONFIG_LOG_LEVEL<=3
# if defined(CONFIG_SIMPLE_LOG_FORMAT)
	#define loge(fmt, ...) klog(fmt, ##__VA_ARGS__)
# else
	#define loge(fmt, ...) klog("err  ", __FILE__, __func__, fmt, ##__VA_ARGS__)
# endif
#else
	#define loge(fmt, ...)
#endif


#endif
