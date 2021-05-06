/**
* Virt I/O driver
*
* Documentation: http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html
*
*/


/*
Alternate implementation of ringbuffer which keeps track of free buffers
- Divide ringbuffer into blocks of minimum allocate size
- Use bitmap to keep track of blocks
- When adding buffer, search for necessary blocks
*/

#include "kernel.h"

#include "virtio.h"

static struct virtio_struct virtio;

static inline void device_reset(ptr_t base)	{ DMAW32(base + VIRTIO_OFF_STATUS, 0); }

static int _init_virtio_dev(ptr_t base, ptr_t size, struct virtio_dev_struct* virt)	{
	uint32_t res;

	mmu_map_dma(base, base + size);

	base += cpu_linear_offset();

	// Check magic value
	DMAR32(base + VIRTIO_OFF_MAGIC, res);
	if(res != VIRTIO_MAGIC)	return -HW_ERROR;

	// Version should be 1 or 2
	DMAR32(base + VIRTIO_OFF_VERSION, res);
	virt->version = res;

	// Get device type and check for sanity
	DMAR32(base + VIRTIO_OFF_DEVICE_ID, res);
	logd("VIR I/O device: %i | version: %i\n", res, virt->version);
	if(res == DEVTYPE_INVALID1 || res == DEVTYPE_INVALID2 || res == DEVTYPE_RESERVED || res >= DEVTYPE_MAX)
		return -HW_ERROR;
	virt->devtype = res;

	virt->initialized = false;
	virt->base = base;
	virt->len = size;
	return OK;
}


int virtio_read_v1(struct virtio_dev_struct* dev, void* buf, size_t len)	{
	size_t i;
	char* p = (char*)buf;
	for(i = 0; i < len; i++)	{
		DMAR8(dev->base + VIRTIO_OFF_CONFIG + i, p[i]);
	}
	return i;
}
int virtio_write_v1(struct virtio_dev_struct* dev, void* buf, size_t len)	{
	size_t i;
	char* p = (char*)buf;
	for(i = 0; i < len; i++)	{
		DMAW8(dev->base + VIRTIO_OFF_CONFIG + i, p[i]);
	}
	return i;
}

static int _virtio_inc_array(void)	{
	virtio.max_devices += 1;
	virtio.devices = (struct virtio_dev_struct*)krealloc(virtio.devices, sizeof(struct virtio_dev_struct) * virtio.max_devices );
	return (virtio.devices != NULL) ? OK : -MEMALLOC;
}

int virtio_register_cb(enum DEVTYPE type, virtio_init_t cb)	{
	virtio.inits[type] = cb;
}

int virtio_generic_init(struct virtio_dev_struct* dev, uint64_t features)	{
	/*
	* From the specification 3.1.1 Driver Requirements: Device Initialization
	*
	* The driver MUST follow this sequence to initialize a device:
	* - Reset the device.
	* - Set the ACKNOWLEDGE status bit: the guest OS has noticed the device.
	* - Set the DRIVER status bit: the guest OS knows how to drive the device.
	* - Read device feature bits, and write the subset of feature bits
	* 	understood by the OS and driver to the device. During this step the driver
	* 	MAY read (but MUST NOT write) the device-specific configuration fields to
	* 	check that it can support the device before accepting it.
	* - Set the FEATURES_OK status bit. The driver MUST NOT accept new feature
	* 	bits after this step
	* - Re-read device status to ensure the FEATURES_OK bit is still set:
	* 	otherwise, the device does not support our subset of features and the
	* 	device is unusable.
	* - Perform device-specific setup, including discovery of virtqueues for the
	* 	device, optional per-bus setup, reading and possibly writing the device’s
	* 	virtio configuration space, and population of virtqueues.
	* - Set the DRIVER_OK status bit. At this point the device is "live".
	*/

	device_reset(dev->base);
	device_acknowledge(dev->base);
	device_set_driver(dev->base);

	uint64_t feat = vio_get_features(dev->base);
	dev->feat.supported = feat;

	feat &= (features | VIRTIO_F_GENERIC_SUPPORTED);
	vio_write_features(dev->base, feat);
	dev->feat.negotiated = feat;

	device_features_ok(dev->base);

	uint32_t s = device_status(dev->base);
	ASSERT_TRUE(s == VIRTIO_STATUS_FEATURES_OK, "Status not correct");

	return OK;
}


ptr_t virtq_alloc_desc(uint32_t qsz)	{
	int pages_pack;

	// Get number of pages we must allocate (minimum 2)
	uint32_t bytes1 = ((qsz * sizeof(struct virtq_desc)) + 6 + (qsz * sizeof(uint16_t)));
	uint32_t bytes2 = (6 + (sizeof(struct virtq_used_elem) * qsz));

	ALIGN_UP_POW2(bytes1, PAGE_SIZE);
	ALIGN_UP_POW2(bytes2, PAGE_SIZE);

	pages_pack = (bytes1 / PAGE_SIZE) + (bytes2 / PAGE_SIZE);

	ptr_t vaddr = vmmap_alloc_pages(
		pages_pack, PROT_RW, VMMAP_FLAG_PHYS_CONTIG | VMMAP_FLAG_ZERO
	);

	return vaddr;
}

int virtq_add_queue(struct virtio_dev_struct* dev, int queue)	{
	ptr_t vaddr = virtq_alloc_desc(dev->virtq->qsz);
	dev->virtq->queues[queue].desc = (struct virtq_desc*)vaddr;
	return OK;
}


int virtq_create_alloc(struct virtio_dev_struct* dev, uint32_t qsz, int pages, int queues)	{
	int i;
	dev->virtq = (struct virtq*)kmalloc(
		sizeof(struct virtq) + (queues * sizeof(struct virtq_queue))
	);

	for(i = 0; i < queues; i++)	{
		dev->virtq->queues[i].idx = 0;
		dev->virtq->queues[i].desc = NULL;
	}

	dev->virtq->ringbuffer = pmm_alloc(pages);
	dev->virtq->ringc = 0;
	dev->virtq->ringm = PAGE_SIZE * pages;

	dev->virtq->qsz = qsz;
	dev->virtq->numqueues = queues;
//	dev->virtq.desc = (struct virtq_desc*)vaddr;
	dev->allocated = true;
	return OK;
}

int virtq_destroy_alloc(struct virtio_dev_struct* dev)	{
	if(!(dev->allocated))	return OK;
	int pages = dev->virtq->ringm / PAGE_SIZE, i;
	ptr_t p = (ptr_t)dev->virtq->ringbuffer;
	if(p)	{
		for(i = 0; i < pages; i++)	{
			pmm_free(p + (i * PAGE_SIZE));
		}
	}
	kfree(dev->virtq);
	return OK;
}

ptr_t virtq_add_buffer(struct virtio_dev_struct* dev, uint32_t bytes, uint16_t flags, int queue, bool updateavail, bool chain)	{
	struct virtq* vq = dev->virtq;
	ptr_t vaddr = (ptr_t)vq->queues[queue].desc;
	int idx = vq->queues[queue].idx;
	int pidx = (idx) ? ((idx - 1) % vq->qsz) : -1;
	int _idx;

	// Ensure that ringbuffer is reasonably well aligned
	ALIGN_UP_POW2(bytes, 32);

	if(idx >= vq->qsz)	{
		logi("Going over qsz\n");
	}
	_idx = idx % vq->qsz;

	//idx %= vq->qsz;

	ptr_t pdata = 0;

	// This is an error in kernel driver
	ASSERT_FALSE(bytes > vq->ringm, "Tried to allocate buffer larger than ringbuffer\n");
	

	// Check if we have enough space remaining in ringbuffer
	// if not, we start at zero again
	// We assume here that the driver has parsed that data already
	if( bytes > (vq->ringm - vq->ringc) )	{
		logw("Beginning from start of ringbuffer and overwriting previous data\n");
		logi("TODO: Caller should copy any address it has stored\n");
		vq->ringc = 0;
	}

	pdata = vq->ringbuffer + vq->ringc;
	vq->ringc += bytes;
	
	struct virtq_desc* desc;
	struct virtq_avail* avail;
	//struct virtq_used* used;

	if(chain && idx > 0)	{
		desc = (struct virtq_desc*)(vaddr + (pidx * sizeof(struct virtq_desc)));
		desc->next = idx;
		desc->flags |= VIRTQ_DESC_F_NEXT;
	}

	desc = (struct virtq_desc*)(vaddr + (_idx * sizeof(struct virtq_desc)));
	desc->paddr = pdata;
	desc->len = bytes;
	desc->flags = flags;
	desc->next = 0;

	if(updateavail)	{
		avail = (struct virtq_avail*)(vaddr + (vq->qsz * sizeof(struct virtq_desc)));
		avail->flags = 0;

		/** idx always increments, and wraps naturally at 65536 */
		avail->idx = idx + 1;
		avail->ring[_idx] = _idx;
	}

	vq->queues[queue].idx += 1;
	dsb();

	return pdata;
}

struct virtq_used* virtq_get_used(struct virtio_dev_struct* dev, int queue)	{
	struct virtq_used* u = NULL;
	struct virtq_used_elem* ret = NULL;
	struct virtq* vq = dev->virtq;
	ptr_t vaddr = (ptr_t)vq->queues[queue].desc;
	uint32_t bytes1 = ((vq->qsz * sizeof(struct virtq_desc)) + 4 + (vq->qsz * sizeof(uint16_t)));
	ALIGN_UP_POW2(bytes1, PAGE_SIZE);
	vaddr += bytes1;


	u = (struct virtq_used*)vaddr;
	return u;
}

int virtio_complete_init(struct virtio_dev_struct* dev)	{
	uint32_t tmp;
	isb();

	DMAW32(dev->base + VIRTIO_OFF_STATUS, VIRTIO_STATUS_DRIVER_OK);

	DMAR32(dev->base + VIRTIO_OFF_STATUS, tmp);
	ASSERT_TRUE(tmp == VIRTIO_STATUS_DRIVER_OK, "");

	isb();
	dsb();

	return OK;
}

int virtq_write_queue(struct virtio_dev_struct* dev, ptr_t paddr, int idx)	{
	uint32_t tmp;
	struct virtq* vq = dev->virtq;

	// Select appropriate register
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_SEL, idx);

	// Read PFN (should be zero on first read)
	DMAR32(dev->base + VIRTIO_OFF_QUEUE_PFN, tmp);
	if(tmp != 0)	return -HW_ERROR;

	// Check that we are within max
	DMAR32(dev->base + VIRTIO_OFF_QUEUE_NUM_MAX, tmp);
	if(tmp == 0)	return -HW_ERROR;

	// This indicates an error in kernel code
	ASSERT_TRUE(vq->qsz <= tmp, "Too high qsz");

	// Write queue size back
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NUM, vq->qsz);

	// Write alignment
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_ALIGN, PAGE_SIZE);

	// Write start of descriptor table
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_PFN, paddr);
	return OK;
}

int virtio_virtq_init(struct virtio_dev_struct* dev)	{
	struct virtq* vq = dev->virtq;
	uint32_t tmp;
	int res, i;
	ptr_t paddr;

	for(i = 0; i < dev->virtq->numqueues; i++)	{
		paddr = mmu_va_to_pa( (ptr_t)(vq->queues[i].desc) );
		res = virtq_write_queue(dev, paddr, i);
		ASSERT_TRUE(res == OK, "error");
	}

	return OK;
}

int init_virtio(void)	{
	virtio.devices = NULL;
	virtio.num_devices = virtio.max_devices = 0;
	struct dtb_node* dtb;
	ptr_t addr, len;
	int i = 0;
	struct virtio_dev_struct tmp = {0};
	while(true)	{
		dtb = dtb_find_name("virtio_mmio@", false, i);
		if(dtb == NULL)	break;
		i++;

		dtb_get_as_reg(dtb, 0, &addr, &len);
		dtb_get_interrupts(dtb, &tmp.irqtype, &tmp.irqno, &tmp.irqflags);

		if(_init_virtio_dev(addr, len, &tmp) == OK)	{
			if(virtio.inits[tmp.devtype] != NULL)	{
				if(virtio.inits[tmp.devtype](&tmp) == OK)	{
					ASSERT_TRUE(_virtio_inc_array() == OK, "Error");
					memcpy( &(virtio.devices[virtio.num_devices]), &tmp, sizeof(struct virtio_dev_struct) );
					virtio.num_devices++;
				}
			}
		}

	}

	logi("virtio done\n");
	return 0;
}

int virtio_intr_status(struct virtio_dev_struct* dev)	{
	uint32_t res = 0;
	DMAR32(dev->base + VIRTIO_OFF_INTR_STATUS, res);
	return res;
}

int virtio_ack_intr(struct virtio_dev_struct* dev)	{
	uint32_t res = 0;
	DMAR32(dev->base + VIRTIO_OFF_INTR_STATUS, res);
	if(res != 0)	{
		DMAW32(dev->base + VIRTIO_OFF_INTR_ACK, res);
	}
	return res;
}
driver_init(init_virtio);
int virtio_exit(void)  {
    kfree(virtio.devices);
	return OK;
}
poweroff_exit(virtio_exit);
