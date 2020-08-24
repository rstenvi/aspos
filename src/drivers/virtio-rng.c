/**
* Virt I/O device for RNG
*/
#include "kernel.h"
#include "virtio.h"

// This will use slightly less than one page for desc and available
#define VRTIO_RNG_NUM_BUFS 225

#define VIRTQ_RNG_BUFFER_PAGES 1

#define VIRTQ_RNG_READ_SIZE 64
#define VIRTW_RNG_CACHE_SIZE 64

struct rng_read {
	void* uaddr;
	size_t left, total;
	int tid;
	struct ringbuf* cache;
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

	if(elem->len > sz && ringbuf_num_bytes(rng_job.cache) < VIRTW_RNG_CACHE_SIZE)	{
		// Copy whatever we have into cache
		// If we copy more than we have space for, we simply overwrite old data
		ringbuf_write(rng_job.cache, (from + sz), (elem->len - sz));
	}

	return rng_job.left;
}

int rng_read(struct vfsopen* o, void* buf, size_t sz)	{
	int res, cbytes, nsize = sz;
	ASSERT_TRUE(sz <= PAGE_SIZE, "Not supported yet");
	struct virtio_dev_struct* dev = &rngdev;

	cbytes = ringbuf_num_bytes(rng_job.cache);
	if(cbytes > 0)	{
		int rlen = MIN(cbytes, nsize);
		rlen = ringbuf_read(rng_job.cache, buf, rlen);
		nsize -= rlen;
		buf += rlen;
	}

	// If we already have enough, we just return
	if(nsize == 0)	return sz;


	rng_job.uaddr = buf;
	rng_job.left = nsize;
	rng_job.total = sz;
	rng_job.tid = current_tid();

	// Kick off read
	virtq_add_buffer(dev, VIRTQ_RNG_READ_SIZE, VIRTQ_DESC_F_WRITE, 0, true);
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 0);

	return -BLOCK_THREAD;
}

int virtio_rng_irq_cb(void)	{
	logd("IRQ rng\n");
	struct virtio_dev_struct* dev = &rngdev;
	struct virtq_used* u = virtq_get_used(dev, 0);
	int idx = dev->virtq->queues[0].idx - 1;
	struct virtq_desc* desc = virtio_get_desc(dev, 0);
	int res;

	res = virtio_intr_status(dev);
	if(FLAG_SET(res, VIRTIO_INTR_STATUS_RING_UPDATE))	{
		res = write_to_user(desc, &(u->used[idx]));
		/*if(res == 0)	{
			thread_wakeup(rng_job.tid, rng_job.total);
		}*/
	}

	// Job we have kicked of is finished, we check if we need to to kick of
	// another one
	else if(res == 0)	{
		if(rng_job.left)	{
			virtq_add_buffer(dev, VIRTQ_RNG_READ_SIZE, VIRTQ_DESC_F_WRITE, 0, true);
			DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 0);
		}
		else	{
			thread_wakeup(rng_job.tid, rng_job.total);
		}
	}
	virtio_ack_intr(dev);
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


	rng_job.cache = ringbuf_alloc(VIRTW_RNG_CACHE_SIZE);
	ASSERT_FALSE(PTR_IS_ERR(rng_job.cache), "Cannot allocate ringbuffer cache");

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
