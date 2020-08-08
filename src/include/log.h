#ifndef __LOG_H
#define __LOG_H

#include "config.h"

#include <stdarg.h>

#ifndef CONFIG_LOG_LEVEL
	#define CONFIG_LOG_LEVEL 0
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
#define kwrite(s) osdata.kputs(s)
#define kprintf(fmt, ...) osdata.printk(fmt, ##__VA_ARGS__)
#define klog(level,fmt,...) \
	mutex_acquire(cpu_loglock()); \
	osdata.printk("%s|%s|%s|", level,__FILE__,__func__); \
	osdata.printk(fmt, ##__VA_ARGS__); \
	mutex_release(cpu_loglock())

#if CONFIG_LOG_LEVEL==0
	/** Log debug information. */
	#define logd(fmt, ...) klog("debug", fmt, ##__VA_ARGS__)
#else
	#define logd(fmt, ...) asm("nop")
#endif

#if CONFIG_LOG_LEVEL<=1
	/** Log information. */
	#define logi(fmt, ...) klog("info ", fmt, ##__VA_ARGS__)
#else
	#define logi(fmt, ...) asm("nop")
#endif

#if CONFIG_LOG_LEVEL<=2
	/** Log warning. */
	#define logw(fmt, ...) klog("warn ", fmt, ##__VA_ARGS__)
#else
	#define logw(fmt, ...) asm("nop")
#endif

#if CONFIG_LOG_LEVEL<=3
	/** Log error. */
	#define loge(fmt, ...) klog("err  ", fmt, ##__VA_ARGS__)
#else
	#define loge(fmt, ...) asm("nop")
#endif


#endif
