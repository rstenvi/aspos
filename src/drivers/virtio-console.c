#include "kernel.h"
#include "virtio.h"

#define QUEUE_IDX_DATA_RX (0)
#define QUEUE_IDX_DATA_TX (1)

#define QUEUE_IDX_CTRL_RX (2)
#define QUEUE_IDX_CTRL_TX (3)

#define VIRTIO_CONSOLE_F_SIZE		 (1 << 0)
#define VIRTIO_CONSOLE_F_MULTIPORT   (1 << 1)
#define VIRTIO_CONSOLE_F_EMERG_WRITE (1 << 2)


#define VIRTIO_CONSOLE_DEVICE_READY  (0)
#define VIRTIO_CONSOLE_DEVICE_ADD    (1)
#define VIRTIO_CONSOLE_DEVICE_REMOVE (2)
#define VIRTIO_CONSOLE_PORT_READY    (3)
#define VIRTIO_CONSOLE_CONSOLE_PORT  (4)
#define VIRTIO_CONSOLE_RESIZE        (5)
#define VIRTIO_CONSOLE_PORT_OPEN     (6)
#define VIRTIO_CONSOLE_PORT_NAME     (7)

struct virtio_console_config {
	uint16_t cols;
	uint16_t rows;
	uint32_t max_nr_ports;
	uint32_t emerg_wr;
};
struct virtio_console_control {
	uint32_t id;    /* Port number */
	uint16_t event; /* The kind of control event */
	uint16_t value; /* Extra information for the event */
};


enum V_STATE {
	V_NOT_CONFIGURED = 0,
	V_READY,
};

struct vconsole {
	int id, qidx;
//	char fname[DEVICE_NAME_MAXLEN];
	struct fs_struct* fs;
};

struct vconsole_job {
	enum JOB_TYPE type;
	struct thread* owner;
	struct vconsole* vc;
//	void* uaddr;
//	size_t len;
	int retval;
};
struct vconsole_meta {
//	enum V_STATE state;
	struct llist* consoles;
	int num_consoles;
	
	struct llist* jobspending;
};

struct vconsole_meta vmeta = {0};

static struct virtio_dev_struct consoledev;

static int read_console_config(struct virtio_dev_struct* dev)	{
	struct virtio_console_config c;
	ptr_t addr = (ptr_t)&c;


	DMAR64(dev->base + VIRTIO_OFF_CONFIG, addr);
	DMAR32(dev->base + VIRTIO_OFF_CONFIG + 8, c.emerg_wr);

	logi("cols: %i rows: %i max: %i emerg: %i\n", c.cols, c.rows, c.max_nr_ports, c.emerg_wr);
	return OK;
}

int vconsole_open(struct vfsopen* o, const char* name, int flags, int mode)	{
	int i = 0, res;
	struct virtio_dev_struct* dev = &consoledev;
	struct vconsole* vc;
	while( (vc = llist_index(vmeta.consoles, i)) != NULL)	{
		if(strcmp(name, vc->fs->name) == 0)	break;
	}
	if(vc != NULL)	{
		TZALLOC_ERR(job, struct vconsole_job);
		job->vc = vc;
		job->owner = current_thread();

		SET_VFS_DATA(o, job);

		// Allow us to receive data on this port
		virtq_add_buffer(dev, 512, VIRTQ_DESC_F_WRITE, vc->qidx + QUEUE_IDX_DATA_RX, true, false);
		DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, vc->qidx + QUEUE_IDX_DATA_RX);

		return o->fd;
	}
	return -USER_FAULT;
}

int vconsole_read(struct vfsopen* o, void* buf, size_t sz)	{
	GET_VFS_DATA(o, struct vconsole, vc);
	struct virtio_dev_struct* dev = &consoledev;
	ptr_t addr;

	return -BLOCK_THREAD;
}
int vconsole_write(struct vfsopen* o, const void* buf, size_t sz)	{
	GET_VFS_DATA(o, struct vconsole_job, job);
	struct virtio_dev_struct* dev = &consoledev;
	ptr_t addr;


	addr = virtq_add_buffer(dev, sz, 0, job->vc->qidx + QUEUE_IDX_DATA_TX, true, false);
	addr += cpu_linear_offset();

	memcpy_from_user((void*)addr, buf, sz);
//	mmu_memcpy(thread_get_user_pgd(vsock->owner), (void*)addr, buf, sz);
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, job->vc->qidx + QUEUE_IDX_DATA_TX);
	return sz;
}

int vconsole_close(struct vfsopen* o)	{
	SET_VFS_DATA(o, NULL);
	return OK;
}
static int __send_ctrl(struct virtio_dev_struct* dev, struct virtio_console_control* ctrl)	{
	ptr_t addr;
	virtq_add_buffer(dev, 64, VIRTQ_DESC_F_WRITE, QUEUE_IDX_CTRL_RX, true, false);
	addr = virtq_add_buffer(dev, sizeof(struct virtio_console_control), 0, QUEUE_IDX_CTRL_TX, true, false);

	memcpy((void*)(addr + cpu_linear_offset()), ctrl, sizeof(struct virtio_console_control));

	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, QUEUE_IDX_CTRL_RX);
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, QUEUE_IDX_CTRL_TX);
	return OK;
}
static int _config_as_ready(struct virtio_dev_struct* dev)	{
	int res;
	struct virtio_console_control ctrl;
	/*
	if(vmeta.state != V_NOT_CONFIGURED)	{
		logi("Tried to register state again\n");
		return -USER_FAULT;
	}*/

	TZALLOC_ERR(job, struct vconsole_job);
	job->type = JOB_FCNTL;
	job->owner = current_thread();
	llist_insert(vmeta.jobspending, job, QUEUE_IDX_CTRL_RX);


	ctrl.id = 0;	// unused
	ctrl.event = VIRTIO_CONSOLE_DEVICE_READY;
	ctrl.value = 1;
	res = __send_ctrl(dev, &ctrl);
	if(res == OK)	{
		return -BLOCK_THREAD;
	}

	return res;
}
int console_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	struct virtio_dev_struct* dev = &consoledev;
	switch(cmd)	{
	case FCNTL_VCONSOLE_INIT:
		res = _config_as_ready(dev);
		break;
	default:
		res = -USER_FAULT;
		break;
	}
	return res;
}

static struct fs_struct virtioconsoledev = {
	.name = "vconsole",
	.open  = vfs_empty_open,
	.fcntl = console_fcntl,
	.perm = ACL_PERM(ACL_CTRL|ACL_READ, ACL_NONE, ACL_NONE),
};

static int __add_device(struct virtio_dev_struct* dev, struct virtio_console_control* ctrl)	{
	int nidx = 0, res;
	if(vmeta.num_consoles > 0)	nidx = 2 + (vmeta.num_consoles * 2);
	TZALLOC_ERR(ins, struct vconsole);
	TZALLOC_ERR(fs, struct fs_struct);
	ins->id = ctrl->id;
	ins->fs = fs;
	ins->qidx = nidx;

	fs->open = vconsole_open;
	fs->read = vconsole_read;
	fs->write = vconsole_write;
	fs->close = vconsole_close;
	fs->perm = ACL_PERM(ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE, ACL_NONE);
	snprintf(fs->name, DEVICE_NAME_MAXLEN, "vconsole-%d", ins->id);
//	strncpy(ins->fname, fs->name, DEVICE_NAME_MAXLEN);

	llist_insert(vmeta.consoles, ins, ins->id);

	// Add queues for RX and TX
	/*
	res = virtq_add_queue(dev, nidx); 
	ASSERT_TRUE(res == OK, "error");
	res = virtq_add_queue(dev, nidx + 1); 
	ASSERT_TRUE(res == OK, "error");
	*/

	// Register the new device
	device_register(fs);

	struct virtio_console_control ctrl2;
	ctrl2.id = ctrl->id;
	ctrl2.event = VIRTIO_CONSOLE_PORT_READY;
	ctrl2.value = 1;
	res = __send_ctrl(dev, &ctrl2);

	return OK;
}
static int __port_ready(struct virtio_dev_struct* dev, struct virtio_console_control* ctrl)	{
	int res = OK;
	if(ctrl->value == 1)	{
/*
		struct virtio_console_control ctrl2;
		ctrl2.id = ctrl->id;
		ctrl2.event = VIRTIO_CONSOLE_PORT_OPEN;
		ctrl2.value = 1;
		res = __send_ctrl(dev, &ctrl2);
		*/
	}
	else	{
		logw("Port cannot be opened\n");
		res = -1;
	}
	return res;
}
static int __handle_ctrl(struct virtio_dev_struct* dev, struct virtio_console_control* ctrl)	{
	int res = OK;
	bool wakeup = true;
	switch(ctrl->event)	{
	case VIRTIO_CONSOLE_DEVICE_ADD:
		res = __add_device(dev, ctrl);
		wakeup = false;
		break;
	case VIRTIO_CONSOLE_PORT_OPEN:
		res = __port_ready(dev, ctrl);
		break;
	default:
		res = -1;
		break;
	}
	struct vconsole_job* job;
	if(wakeup)	{
		job = llist_remove(vmeta.jobspending, QUEUE_IDX_CTRL_RX);
		if(!PTR_IS_ERR(job))	{
			thread_wakeup(job->owner->id, res);
			kfree(job);
		}
	}
	return res;
}

static int _handle_cb(struct virtio_dev_struct* dev)	{
	int sidx = 0, res;
	struct virtq_used* u;
	struct virtq_used_elem* elem;
	struct virtq_desc* desc;
//	if(vmeta.state == V_NOT_CONFIGURED)	{
		sidx = QUEUE_IDX_CTRL_RX;
//	}
//	else	{
//		PANIC("Need to find idx\n");
//	}

	res = virtio_intr_status(dev);
	virtio_ack_intr(dev);
	if(FLAG_SET(res, VIRTIO_INTR_STATUS_RING_UPDATE))	{
		u = virtq_get_used(dev, sidx);
		elem = &(u->used[u->idx-1]);
		desc = virtio_get_desc(dev, sidx, elem->idx);

		if(sidx == QUEUE_IDX_CTRL_RX)	{
			struct virtio_console_control* ctrl = (struct virtio_console_control*)(desc->paddr + cpu_linear_offset());
			if(elem->len < sizeof(struct virtio_console_control))	{
				logw("Received too little data: %i\n", elem->len);
			}
			else	{
				res = __handle_ctrl(dev, ctrl);
			}
		}
	}
	else if(res == 0)	{

	}
	return OK;
}


int virtio_console_irq_cb(int irqno)	{
	//logi("IRQ console\n");
	return _handle_cb(&consoledev);
	/*
	int res, idx;
	struct virtio_dev_struct* dev = &consoledev;
	struct virtq_used* u = virtq_get_used(dev, QUEUE_IDX_CTRL_RX);
	idx = u->idx - 1;
	struct virtq_used_elem* elem = &(u->used[idx]);
	struct virtq_desc* desc = virtio_get_desc(dev, QUEUE_IDX_CTRL_RX, elem->idx);
*/
	return OK;
}


int virtio_console_init(struct virtio_dev_struct* dev)	{
	int res;
	virtio_generic_init(dev, VIRTIO_CONSOLE_F_SIZE | VIRTIO_CONSOLE_F_MULTIPORT);

	read_console_config(dev);

#define NUM_QUEUES (4)
#define NUM_PAGES  (4)
	res = virtq_create_alloc(dev, 200, NUM_PAGES, NUM_QUEUES);
	ASSERT_TRUE(res == OK, "error");

	res = virtq_add_queue(dev, 0); 
	ASSERT_TRUE(res == OK, "error");
	res = virtq_add_queue(dev, 1); 
	ASSERT_TRUE(res == OK, "error");

	// Only add control queues
	res = virtq_add_queue(dev, 2); 
	ASSERT_TRUE(res == OK, "error");
	res = virtq_add_queue(dev, 3); 
	ASSERT_TRUE(res == OK, "error");


	res = virtio_virtq_init(dev);
	ASSERT_TRUE(res == OK, "error");

	res = virtio_complete_init(dev);
	ASSERT_TRUE(res == OK, "error");

	dev->irqno += gic_spi_offset();
	gic_set_priority(dev->irqno, 1);
	gic_clear_intr(dev->irqno);
	gic_enable_intr(dev->irqno);
	gic_register_cb(dev->irqno, virtio_console_irq_cb);

	vmeta.consoles = llist_alloc();
	vmeta.jobspending = llist_alloc();

	memcpy(&consoledev, dev, sizeof(struct virtio_dev_struct));

	device_register( &virtioconsoledev );

	return OK;
}

int virtio_console_register(void)   {
	virtio_register_cb(CONSOLE, virtio_console_init);
	return OK;
}

early_hw_init(virtio_console_register);
