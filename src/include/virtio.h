#ifndef __VIRTIO_H
#define __VIRTIO_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

#define VIRTIO_OFF_MAGIC              0x000
#define VIRTIO_OFF_VERSION            0x004
#define VIRTIO_OFF_DEVICE_ID          0x008
#define VIRTIO_OFF_VENDOR_ID          0x00c

// These were called HOST in v1
#define VIRTIO_OFF_DEVICE_FEATURES    0x010
#define VIRTIO_OFF_DEVICE_FEATURE_SEL 0x014

// These were called GUEST in v1
#define VIRTIO_OFF_DRIVER_FEATURES    0x020
#define VIRTIO_OFF_DRIVER_FEATURE_SEL 0x024

// Only in v1
#define VIRTIO_OFF_GUEST_PAGE_SIZE    0x028

#define VIRTIO_OFF_QUEUE_SEL          0x030
#define VIRTIO_OFF_QUEUE_NUM_MAX      0x034
#define VIRTIO_OFF_QUEUE_NUM          0x038

// Only v1
#define VIRTIO_OFF_QUEUE_ALIGN        0x03c
#define VIRTIO_OFF_QUEUE_PFN          0x040

// Only v2
#define VIRTIO_OFF_QUEUE_READY        0x044


#define VIRTIO_OFF_QUEUE_NOTIFY       0x050
#define VIRTIO_OFF_INTR_STATUS        0x060
#define VIRTIO_OFF_INTR_ACK           0x064
#define VIRTIO_OFF_STATUS             0x070

// Only in v2
#define VIRTIO_OFF_QUEUE_DESC_LOW     0x080
#define VIRTIO_OFF_QUEUE_DESC_HIGH    0x084
#define VIRTIO_OFF_QUEUE_DRIVER_LOW   0x090
#define VIRTIO_OFF_QUEUE_DRIVER_HIGH  0x094
#define VIRTIO_OFF_QUEUE_DEVICE_LOW   0x0a0
#define VIRTIO_OFF_QUEUE_DEVICE_HIGH  0x0a4
#define VIRTIO_OFF_CONFIG_GEN         0x0fc


#define VIRTIO_OFF_CONFIG             0x100


#define VIRTIO_MAGIC 0x74726976

#define VIRTIO_STATUS_ACKNOWLEDGE        1
#define VIRTIO_STATUS_DRIVER             2
#define VIRTIO_STATUS_FAILED             128
#define VIRTIO_STATUS_FEATURES_OK        8
#define VIRTIO_STATUS_DRIVER_OK          4
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64


// Feature bits
#define VIRTIO_F_NOTIFY_ON_EMPTY    (1 << 24)
#define VIRTIO_F_ANY_LAYOUT         (1 << 27)
#define VIRTIO_F_RING_INDIRECT_DESC (1 << 28)
#define VIRTIO_F_RING_EVENT_IDX     (1 << 29)
#define VIRTIO_F_VERSION_1          (1 << 32)
#define VIRTIO_F_RING_PACKED        (1 << 34)

#define VIRTIO_F_GENERIC_SUPPORTED (VIRTIO_F_NOTIFY_ON_EMPTY | VIRTIO_F_ANY_LAYOUT)

/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT   1
/* This marks a buffer as device write-only (otherwise device read-only). */
#define VIRTQ_DESC_F_WRITE     2
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT   4



#define VIRTIO_INTR_STATUS_RING_UPDATE (1 << 0)
#define VIRTIO_INTR_STATUS_CONF_UPDATE (1 << 1)

enum DEVTYPE {
	DEVTYPE_RESERVED = 0,
	NETWORK_CARD,
	BLOCK_DEVICE,
	CONSOLE,
	ENTROPY,
	MEMORY_BALLOON_TRAD,
	IOMEMORY,
	RPMSG,
	SCSI_HOST,
	TRANSPORT_9P,
	MAC80211_WLAN,
	RPROC_SERIAL,
	VIRTIO_CAIF,
	MEMORY_BALLOON,
	GPU_DEVICE,
	TIMER,
	INPUT,
	SOCKET,
	CRYPTO,
	SIGNAL_DIST_MOD,
	PSTORE,
	IOMMU,
	MEMORY,
	DEVTYPE_MAX,
};

struct virtq_queue {
	struct virtq_desc* desc;
	int idx;
};


struct virtq {
	uint32_t qsz;
//	uint16_t idx, idx2;
	ptr_t ringbuffer;
	int ringc, ringm;
	int numqueues;
	struct virtq_queue queues[];

//	struct virtq_desc* desc;
//	struct virtq_desc* desc2;
};

struct virtio_dev_struct {
	ptr_t base, len;
	uint32_t irqtype, irqno, irqflags;
	int version;
	struct {
		uint64_t supported;
		uint64_t negotiated;
	} feat;
	enum DEVTYPE devtype;
	bool initialized;

	struct virtq* virtq;

	/**
	* Individual driver can use this to maintain a state.
	*/
	void* state;
};

typedef int (*virtio_init_t)(struct virtio_dev_struct*);

struct virtio_struct {
	/**
	* Array of all devices we have seen.
	*/
	struct virtio_dev_struct* devices;
	size_t num_devices, max_devices;

	/**
	* All the init function which has been registered by device types.
	*/
	virtio_init_t inits[DEVTYPE_MAX];
};

struct virtq_desc {
	uint64_t paddr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
} __attribute__((packed));

struct virtq_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[];
} __attribute__((packed));

struct virtq_used_elem {
	uint32_t idx;
	uint32_t len;
} __attribute__((packed));

struct virtq_used {
	uint16_t flags;
	uint16_t idx;
	struct virtq_used_elem used[];
} __attribute__((packed));


static inline void device_acknowledge(ptr_t base) {
	DMAW32(base + VIRTIO_OFF_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
}
static inline void device_set_driver(ptr_t base) {
	DMAW32(base + VIRTIO_OFF_STATUS, VIRTIO_STATUS_DRIVER);
}
static inline void device_set_driver_ok(ptr_t base) {
	DMAW32(base + VIRTIO_OFF_STATUS, VIRTIO_STATUS_DRIVER_OK);
}
static inline void device_features_ok(ptr_t base) {
	DMAW32(base + VIRTIO_OFF_STATUS, VIRTIO_STATUS_FEATURES_OK);
}
static inline uint32_t device_features(ptr_t base)	{
	uint32_t r;
	DMAR32(base + VIRTIO_OFF_DEVICE_FEATURES, r);
	logi("r = 0x%x\n", r);
	return r;
}
static inline void device_set_features(ptr_t base, uint32_t r) {
	DMAW32(base + VIRTIO_OFF_DRIVER_FEATURES, r);
}

static inline uint32_t device_status(ptr_t base)	{
	uint32_t r;
	DMAR32(base + VIRTIO_OFF_STATUS, r);
	return r;
}

int virtio_register_cb(enum DEVTYPE type, virtio_init_t cb);
int virtio_generic_init(struct virtio_dev_struct* dev, uint64_t features);


static inline uint64_t vio_get_features(ptr_t base)	{
	uint64_t ret = 0;
	uint32_t tmp = 0;
	DMAW32(base + VIRTIO_OFF_DEVICE_FEATURE_SEL, 1);
	DMAR32(base + VIRTIO_OFF_DEVICE_FEATURES, tmp);
	ret = (uint64_t)(tmp) << 32;
	DMAW32(base + VIRTIO_OFF_DEVICE_FEATURE_SEL, 0);
	DMAR32(base + VIRTIO_OFF_DEVICE_FEATURES, tmp);
	ret |= (uint64_t)tmp;
	logi("features got 0x%lx\n", ret);
	return ret;
}

static inline void vio_write_features(ptr_t base, uint64_t val)	{
	logi("features set 0x%lx\n", val);
	uint32_t v = (uint32_t)(val & 0xffffffff);
	DMAW32(base + VIRTIO_OFF_DRIVER_FEATURE_SEL, 0);
	DMAR32(base + VIRTIO_OFF_DRIVER_FEATURES, v);

	val >>= 32;
	v = (uint32_t)(val & 0xffffffff);
	DMAW32(base + VIRTIO_OFF_DRIVER_FEATURE_SEL, 1);
	DMAR32(base + VIRTIO_OFF_DRIVER_FEATURES, v);
}

int virtio_complete_init(struct virtio_dev_struct* dev);
int virtio_virtq_init(struct virtio_dev_struct* dev);
struct virtq_used* virtq_get_used(struct virtio_dev_struct* dev, int queue);
ptr_t virtq_add_buffer(struct virtio_dev_struct* dev, uint32_t bytes, uint16_t flags, int queue, bool updateavail);
int virtq_create_alloc(struct virtio_dev_struct* dev, uint32_t qsz, int pages, int queue);
int virtio_ack_intr(struct virtio_dev_struct* dev);
ptr_t virtq_alloc_desc(uint32_t qsz);
int virtq_write_queue(struct virtio_dev_struct* dev, ptr_t paddr, int idx);

int virtq_add_queue(struct virtio_dev_struct* dev, int queue);
int virtio_intr_status(struct virtio_dev_struct* dev);
int virtio_read_v1(struct virtio_dev_struct* dev, void* buf, size_t len);

static inline struct virtq_desc* virtio_get_desc(struct virtio_dev_struct* dev, int queue, int idx) {
	ptr_t start = (ptr_t)(dev->virtq->queues[queue].desc);
	start += (idx * sizeof(struct virtq_desc));
	return (struct virtq_desc*)(start);
}

static inline int virtio_read_config(struct virtio_dev_struct* dev, void* buf, size_t len)	{
	return virtio_read_v1(dev, buf, len);
}

#endif
