/**
* Virt I/O device for RNG
*/
#include "kernel.h"
#include "virtio.h"

// This will use slightly less than one page for desc and available
#define VRTIO_RNG_NUM_BUFS 225

#define VIRTQ_RNG_BUFFER_PAGES 1

#define VIRTQ_RNG_READ_SIZE 64
#define VIRTW_RNG_CACHE_SIZE 128

struct rng_read {
	void* uaddr;
	size_t left, total;
	int tid;
};

/**
* Global state for VIRTIO entropy device.
*/
struct virtiorng_data {
	/**
	* We use a simple FIFO list for the jobs. We want to complete the jobs in
	* order, but we don't need to track which thread should get what data. If
	* one thread kicks of a job which reads 64B of random data, but only need
	* 4B, a separate thread can have the remaining 60B.
	*/
	struct XIFO* jobs;

	/**
	* Maintain a cache of received random bytes which have not been ready by any
	* thread. Because we always read in VIRTQ_RNG_READ_SIZE blocks, any extra
	* data not used by the thread is appended to this cache.
	*/
	struct ringbuf* cache;
};


struct virtio_dev_struct rngdev;

static struct virtiorng_data* alloc_data_obj(void)	{
	TMALLOC(ret, struct virtiorng_data);
	ASSERT_VALID_PTR(ret);

	ret->jobs = xifo_alloc(2, 2);
	ASSERT_VALID_PTR(ret->jobs);

	ret->cache = ringbuf_alloc(VIRTW_RNG_CACHE_SIZE);
	ASSERT_VALID_PTR(ret->cache);

	return ret;
}

static struct rng_read* alloc_read_job(void* uaddr, size_t total, size_t left)	{
	TMALLOC(ret, struct rng_read);
	ASSERT_VALID_PTR(ret);

	ret->uaddr = uaddr;
	ret->total = total;
	ret->left = left;
	ret->tid = current_tid();

	return ret;
}

int write_to_user(struct virtq_desc* desc, struct virtq_used_elem* elem, struct virtiorng_data* data, struct rng_read* job)	{
	if(job->left == 0)	return 0;

	void* from = (void*)(desc->paddr + cpu_linear_offset());
	size_t sz = MIN(job->left, elem->len);

	memcpy_to_user(job->uaddr, from, sz);

	job->left -= sz;
	job->uaddr += sz;

	if(elem->len > sz)	{
		// Copy whatever we have into cache
		// If we copy more than we have space for, we simply overwrite old data
		ringbuf_write(data->cache, (from + sz), (elem->len - sz));
	}

	return job->left;
}

int rng_read(struct vfsopen* o, void* buf, size_t sz)	{
	int res, cbytes, nsize = sz, rlen;
	ASSERT_TRUE(sz <= PAGE_SIZE, "Not supported yet");
	struct rng_read* job;
	struct virtio_dev_struct* dev = &rngdev;
	struct virtiorng_data* data = (struct virtiorng_data*)dev->state;

	// Try and read whatever we have collected and copy to user
	rlen = ringbuf_read(data->cache, buf, nsize);
	nsize -= rlen;
	buf += rlen;

	// If we already have enough, we just return
	if(nsize == 0)	return sz;

	// If we get here, we must create a job
	job = alloc_read_job(buf, sz, nsize);
	xifo_push_back(data->jobs, (void*)job);

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
	struct virtq_desc* desc = virtio_get_desc(dev, 0, u->used[idx].idx);
	int res;
	struct virtiorng_data* data = (struct virtiorng_data*)dev->state;
	struct rng_read* job;

	/*
	* If we don't have a job waiting for data, we just acknowledge the IRQ and
	* return
	*/
	job = xifo_peep_front(data->jobs);
	if(PTR_IS_ERR(job))	{
		virtio_ack_intr(dev);
		return OK;
	}

	res = virtio_intr_status(dev);
	if(FLAG_SET(res, VIRTIO_INTR_STATUS_RING_UPDATE))	{
		res = write_to_user(desc, &(u->used[idx]), data, job);
	}

	// Job we have kicked of is finished, we check if we need to to kick of
	// another one
	else if(res == 0)	{
		if(job->left)	{
			virtq_add_buffer(dev, VIRTQ_RNG_READ_SIZE, VIRTQ_DESC_F_WRITE, 0, true);
			DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 0);
		}
		else	{
			job = xifo_pop_front(data->jobs);
			thread_wakeup(job->tid, job->total);
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

	struct virtiorng_data* data = alloc_data_obj();
	dev->state = (void*)data;

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
