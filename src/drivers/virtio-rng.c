/**
* Virt I/O device for RNG
*/
#include "kernel.h"
#include "virtio.h"

// This will use slightly less than one page for desc and available
#define VRTIO_RNG_NUM_BUFS 225

#define VIRTQ_RNG_BUFFER_PAGES 1

struct rng_read {
	void* uaddr;
	size_t left, total;
	int tid;
};

struct virtio_dev_struct rngdev;
struct rng_read rng_job = {0};

int write_to_user(struct virtq_desc* desc, struct virtq_used_elem* elem)	{
	if(rng_job.left == 0)	return 0;

	void* from = (void*)(desc->paddr + cpu_linear_offset());
	size_t sz = MIN(rng_job.left, elem->len);

	memcpy(rng_job.uaddr, from, sz);

	rng_job.left -= sz;
	rng_job.uaddr += sz;
	return rng_job.left;
}

int rng_read(struct vfsopen* o, void* buf, size_t sz)	{
	int res;
	ASSERT_TRUE(sz <= PAGE_SIZE, "Not supported yet");
	struct virtio_dev_struct* dev = &rngdev;

	rng_job.uaddr = buf;
	rng_job.left = rng_job.total = sz;
	rng_job.tid = current_tid();

	// TODO: We might already have some data left over, we should try and copy
	// that before we start a new request

	// Kick off read
	virtq_add_buffer(dev, 64, VIRTQ_DESC_F_WRITE, 0, true);
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 0);

	return -BLOCK_THREAD;
}

int virtio_rng_irq_cb(void)	{
	logi("IRQ rng\n");
	struct virtio_dev_struct* dev = &rngdev;
	struct virtq_used* u = virtq_get_used(dev, 0);
	int idx = dev->virtq->queues[0].idx - 1;
	struct virtq_desc* desc = virtio_get_desc(dev, 0);
	uint64_t* p = (uint64_t*)(desc->paddr + cpu_linear_offset());
	bool tr = false;
	int res;

	res = virtio_ack_intr(dev);
	if(FLAG_SET(res, VIRTIO_INTR_STATUS_RING_UPDATE))	{
		res = write_to_user(desc, &(u->used[idx]));
		if(res > 0) {
			virtq_add_buffer(dev, 64, VIRTQ_DESC_F_WRITE, 0, true);
			DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 0);
		}
		else if(res == 0)	{
			thread_wakeup(rng_job.tid, rng_job.total);
		}
	}
	return OK;
}

static struct fs_struct virtiorngdev = {
	.name = "random",
	.read = rng_read,
};


int virtio_rng_init(struct virtio_dev_struct* dev)	{
	int res;
	virtio_generic_init(dev, 0);

	res = virtq_create_alloc(dev, VRTIO_RNG_NUM_BUFS, VIRTQ_RNG_BUFFER_PAGES, 1);
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
	gic_register_cb(dev->irqno, virtio_rng_irq_cb);

	memcpy(&rngdev, dev, sizeof(struct virtio_dev_struct));

	device_register( &virtiorngdev );
	return OK;
}

/*
* Register callback in virtio
*/
int virtio_rng_register(void)	{
	virtio_register_cb(ENTROPY, virtio_rng_init);
	return OK;
}

early_hw_init(virtio_rng_register);
