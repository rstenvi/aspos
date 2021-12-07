#ifndef __ACL_H
#define __ACL_H



//#define CONFIG_SUPPORT_USERS 1
//#define CONFIG_SUPPORT_SYSCALL_FILTER 1
//#define CONFIG_DRIVER_USERID_AUTO_INCREMENT 1

struct user_id	{
	uid_t uid;
	gid_t gid;
};

struct kern_user_struct	{
	struct user_id real;
#if defined(CONFIG_SUPPORT_SYSCALL_FILTER)
	sysfilter_t filter;
#endif
	int refcount;
	mutex_t lock;
};


enum USERID {
	USERID_ROOT = 0,
	USERID_ADM,
	USERID_LAST,
};

#define ACL_CTRL  (8)
#define ACL_READ  (4)
#define ACL_WRITE (2)
#define ACL_EXEC  (1)
#define ACL_NONE  (0)

typedef uint16_t access_t;

#define ACL_BITS      (4)
#define ACL_MASK      ((1 << ACL_BITS) - 1)
#define ACL_OWNER_OFF (8)
#define ACL_OWNER_MASK (ACL_MASK << ACL_OWNER_OFF)

#define ACL_GROUP_OFF (4)
#define ACL_GROUP_MASK (ACL_MASK << ACL_GROUP_OFF)

#define ACL_WORLD_OFF (0)
#define ACL_WORLD_MASK (ACL_MASK << ACL_WORLD_OFF)

#define ACL_OWNER_VAL(n) ((n & ACL_OWNER_MASK) >> ACL_OWNER_OFF)
#define ACL_GROUP_VAL(n) ((n & ACL_GROUP_MASK) >> ACL_GROUP_OFF)
#define ACL_WORLD_VAL(n) ((n & ACL_WORLD_MASK) >> ACL_WORLD_OFF)

#define ACL_OWNER_CONTROL(n)    (ACL_WORLD_VAL(n) & ACL_CTRL)
#define ACL_OWNER_READABLE(n)   (ACL_OWNER_VAL(n) & ACL_READ)
#define ACL_OWNER_WRITABLE(n)   (ACL_OWNER_VAL(n) & ACL_WRITE)
#define ACL_OWNER_EXECUTABLE(n) (ACL_OWNER_VAL(n) & ACL_EXEC)

#define ACL_GROUP_CONTROL(n)    (ACL_WORLD_VAL(n) & ACL_CTRL)
#define ACL_GROUP_READABLE(n)   (ACL_GROUP_VAL(n) & ACL_READ)
#define ACL_GROUP_WRITABLE(n)   (ACL_GROUP_VAL(n) & ACL_WRITE)
#define ACL_GROUP_EXECUTABLE(n) (ACL_GROUP_VAL(n) & ACL_EXEC)

#define ACL_WORLD_CONTROL(n)    (ACL_WORLD_VAL(n) & ACL_CTRL)
#define ACL_WORLD_READABLE(n)   (ACL_WORLD_VAL(n) & ACL_READ)
#define ACL_WORLD_WRITABLE(n)   (ACL_WORLD_VAL(n) & ACL_WRITE)
#define ACL_WORLD_EXECUTABLE(n) (ACL_WORLD_VAL(n) & ACL_EXEC)

#define ACL_SET_X(v,off) (((v) & ACL_MASK) << off)

#define ACL_SET_OWNER(v) ACL_SET_X(v,ACL_OWNER_OFF)
#define ACL_SET_GROUP(v) ACL_SET_X(v,ACL_GROUP_OFF)
#define ACL_SET_WORLD(v) ACL_SET_X(v,ACL_WORLD_OFF)

#define ACL_PERM(owner,group,world) ACL_SET_OWNER(owner) | ACL_SET_GROUP(group) | ACL_SET_WORLD(world)

#define DRIVER_DEFAULT_PERM ACL_PERM(ACL_READ|ACL_WRITE|ACL_CTRL, ACL_READ, ACL_NONE)

enum ACL_GRP	{
	ACL_NO = 0,
	ACL_OWNER,
	ACL_GROUP,
	ACL_WORLD,
};

#endif
