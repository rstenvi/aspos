#ifndef __SYSCALLS_H
#define __SYSCALLS_H

#define SYS_OPEN   0
#define SYS_CLOSE  1
#define SYS_READ   2
#define SYS_WRITE  3
#define SYS_SBRK   4
#define SYS_ISATTY 5
#define SYS_FSTAT  6
#define SYS_EXIT   7

#define SYS_LSEEK  8

#define SYS_POWEROFF 9

#define SYS_SLEEP_TICK 10

#define SYS_NEW_THREAD  11
#define SYS_EXIT_THREAD 12

#define SYS_SLEEP_MS 13

#define SYS_YIELD 14

#define SYS_DUP 15

#define SYS_GET_CHAR 16
#define SYS_PUT_CHAR 17


#define SYS_WAIT_TID 18
#define SYS_GET_TID 19

#define SYS_CONF_THREAD 20

#define SYS_FCNTL 21

#endif
