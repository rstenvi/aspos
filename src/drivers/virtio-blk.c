/**
* Virt I/O device for RNG
*/
#include "kernel.h"
#include "virtio.h"
#include "vfs.h"

#define VIRTIO_BLK_F_SIZE_MAX   (1<<1)
#define VIRTIO_BLK_F_SEG_MAX    (1<<2)
#define VIRTIO_BLK_F_GEOMETRY   (1<<4)
#define VIRTIO_BLK_F_RO         (1<<5)
#define VIRTIO_BLK_F_BLK_SIZE   (1<<6)
#define VIRTIO_BLK_F_FLUSH      (1<<9)
#define VIRTIO_BLK_F_TOPOLOGY   (1<<10)
#define VIRTIO_BLK_F_CONFIG_WCE (1<<11)


/* Legacy interface */
#define VIRTIO_BLK_F_BARRIER (1<<0)
#define VIRTIO_BLK_F_SCSI    (1<<7)


#define VIRTIO_BLK_SUPP_FEATURES \
	(VIRTIO_BLK_F_SIZE_MAX | VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_GEOMETRY | \
	VIRTIO_BLK_F_RO | VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_TOPOLOGY | \
	VIRTIO_BLK_F_CONFIG_WCE | VIRTIO_BLK_F_BARRIER | VIRTIO_BLK_F_SCSI)


#define BLK_UNIT_SIZE (512)



struct virtio_blk_geometry {
	uint16_t cylinders;
	uint8_t heads;
	uint8_t sectors;
} __attribute__((packed));

struct virtio_blk_topology {
	// # of logical blocks per physical block (log2)
	uint8_t physical_block_exp;
	
	// offset of first aligned logical block
	uint8_t alignment_offset;
	
	// suggested minimum I/O size in blocks
	uint16_t min_io_size;

	// optimal (suggested maximum) I/O size in blocks
	uint32_t opt_io_size;
} __attribute__((packed));

struct virtio_blk_config {
	/**
	* Size of disk represented as Number of 512B sectors.
	* This field is always present, the presence of the others depend on the
	* feature bits.
	*/
	uint64_t capacity;
	uint32_t size_max;
	uint32_t seg_max;
	struct virtio_blk_geometry geometry;

	/**
	* Optimal block size to use.
	* Present if VIRTIO_BLK_F_BLK_SIZE has been negotiated.
	* This is only the optimal value however, the unit size is always 512B.
	*/
	uint32_t blk_size;
	struct virtio_blk_topology topology;
	uint8_t writeback;
} __attribute__((packed));


// Command in virtio_blk_req->type
#define VIRTIO_BLK_T_IN           0
#define VIRTIO_BLK_T_OUT          1
#define VIRTIO_BLK_T_FLUSH        4


// status written by the device in virtio_blk_req->status
#define VIRTIO_BLK_S_OK        0
#define VIRTIO_BLK_S_IOERR     1
#define VIRTIO_BLK_S_UNSUPP    2

struct virtio_blk_req {
	/** Type of command */
	uint32_t type;
	uint32_t reserved;

	/** Sector index to use, starting at index 0. */
	uint64_t sector;
	uint8_t data[512];

	/** Status written by device */
	uint8_t status;
} __attribute__((packed));



struct virtio_dev_struct blkdev;


struct blk_job	{
	int tid;
	void* uaddr;
	size_t left, total;
	enum JOB_TYPE type;
	void* devresult;
};

struct blk_device {
	volatile uint8_t lock;
	struct blk_job job;
};

struct blk_device blkdevice;

static inline struct blk_job* _get_job(void) { return &(blkdevice.job); }

static int _create_job(void* addr, size_t sz, enum JOB_TYPE type)	{
	// TODO: Need to be able to run multiple concurrently
	struct blk_job* j = &(blkdevice.job);
	ASSERT_TRUE(j->type == JOB_NONE, "error");

	j->tid = current_tid();
	j->left = j->total = sz;
	j->uaddr = addr;
	j->type = type;
	j->devresult = NULL;
	return OK;
}

int blk_read(struct vfsopen* o, void* buf, size_t sz)	{
	int res;
	struct virtio_blk_req* req;
	struct virtio_dev_struct* dev = &blkdev;
	ptr_t devresult;
	ptr_t preq;

	mutex_acquire(&blkdevice.lock);
	_create_job(buf, sz, JOB_READ);

	preq = virtq_add_buffer(dev, 4+4+8, 0, 0, true);
	devresult = virtq_add_buffer(dev, 513, VIRTQ_DESC_F_WRITE, 0, false);

	struct blk_job* j = &(blkdevice.job);
	j->devresult = (void*)(devresult + cpu_linear_offset());

	req = (struct virtio_blk_req*)(cpu_linear_offset() + preq);
	memset((void*)req, 0x00, sizeof(struct virtio_blk_req));

	req->status = 0xff;
	req->type |= VIRTIO_BLK_T_IN;
	req->sector = vfs_offset(o);

	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 0);

	return -BLOCK_THREAD;
}

int blk_write(struct vfsopen* o, const void* buf, size_t sz)	{
	int res;
	struct virtio_blk_req* req;
	size_t rsz;
	struct virtio_dev_struct* dev = &blkdev;
	ptr_t devresult, preq;
	mutex_acquire(&blkdevice.lock);

	_create_job((void*)buf, sz, JOB_WRITE);

	rsz = MIN(sz, BLK_UNIT_SIZE);
	preq = virtq_add_buffer(dev, 4+4+8, 0, 0, true);
	virtq_add_buffer(dev, 512, 0, 0, false);
	devresult = virtq_add_buffer(dev, 1, VIRTQ_DESC_F_WRITE, 0, false);

	struct blk_job* j = &(blkdevice.job);
	j->devresult = (void*)(devresult + cpu_linear_offset());

	req = (struct virtio_blk_req*)(cpu_linear_offset() + preq);
	memset((void*)req, 0x00, sizeof(struct virtio_blk_req));

	req->status = 0xff;
	req->type |= VIRTIO_BLK_T_OUT;
	req->sector = vfs_offset(o);
	memcpy_from_user(req->data, buf, rsz);

	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 0);

	return -BLOCK_THREAD;

}

int virtio_blk_irq_cb(void)	{
	logd("BLK IRQ\n");
	struct virtio_dev_struct* dev = &blkdev;
	int res;
	int idx = dev->virtq->queues[0].idx - 1;
	struct virtq_used* u = virtq_get_used(dev, 0);
	struct virtq_desc* desc = virtio_get_desc(dev, 0, idx);


	u->idx = 3;

	res = virtio_intr_status(dev);
	if(FLAG_SET(res, VIRTIO_INTR_STATUS_RING_UPDATE))	{
		struct blk_job* j = _get_job();
		// We always read/write in these unit sizes

		uint8_t* dres = (uint8_t*)j->devresult;
		uint8_t retcode;
		if(j->type == JOB_READ)		retcode = dres[512];
		else						retcode = dres[0];

		if(retcode != 0)	{
			logw("Driver returned %i\n", retcode);
		}
		else if(j->type == JOB_READ)	{
			memcpy_to_user(j->uaddr, j->devresult, MIN(j->left, BLK_UNIT_SIZE));
		}
		j->left -= MIN(j->left, BLK_UNIT_SIZE);

		// Unlock the device for new operations
		mutex_release(&blkdevice.lock);
		if(j->type != JOB_NONE && (j->left == 0 || retcode != 0))	{
			int tid = j->tid;
			j->type = JOB_NONE;
			thread_wakeup(tid, (retcode == 0) ? j->total : -1);
		}
	}
	virtio_ack_intr(dev);
	return 0;
}

static struct fs_struct virtioblkdev = {
	.name = "block",
	.read = blk_read,
	.write = blk_write,
};


int virtio_blk_init(struct virtio_dev_struct* dev)	{
	int res;
	struct virtio_blk_config config;

	virtio_generic_init(dev, VIRTIO_BLK_SUPP_FEATURES);

	virtio_read_config(dev, (void*)&config, sizeof(struct virtio_blk_config));

	logi("Device size: 0x%lx\n", (ptr_t)config.capacity * BLK_UNIT_SIZE);
	if(FLAG_SET(dev->feat.negotiated, VIRTIO_BLK_F_BLK_SIZE))	{
		logi("Block size: %i\n", config.blk_size);
	}
	if(FLAG_SET(dev->feat.negotiated, VIRTIO_BLK_F_RO))	{
		logi("Device RO\n");
	}
	else	{
		logi("Device RW\n");
	}

	res = virtq_create_alloc(dev, 225, 1, 1);
	ASSERT_TRUE(res == OK, "error");

	res = virtq_add_queue(dev, 0);
	ASSERT_TRUE(res == OK, "error");

	res = virtio_virtq_init(dev);
	ASSERT_TRUE(res == OK, "error");


	res = virtio_complete_init(dev);
	ASSERT_TRUE(res == OK, "error");


	dev->irqno += gic_spi_offset();
	gic_set_priority(dev->irqno, 1);
	gic_clear_intr(dev->irqno);
	gic_enable_intr(dev->irqno);
	gic_register_cb(dev->irqno, virtio_blk_irq_cb);

	memcpy(&blkdev, dev, sizeof(struct virtio_dev_struct));

	memset(&blkdevice, 0x00, sizeof(struct blk_device));

	device_register( &virtioblkdev );
	return OK;
}

/*
* Register callback in virtio
*/
int virtio_blk_register(void)	{
	virtio_register_cb(BLOCK_DEVICE, virtio_blk_init);
	return OK;
}

early_hw_init(virtio_blk_register);
