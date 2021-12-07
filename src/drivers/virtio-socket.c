#include "kernel.h"
#include "virtio.h"

#define SOCKET_QSZ (8)
#define NUM_QUEUES (3)
#define NUM_PAGES  (2)
#define QUEUE_RX          (0)
#define QUEUE_TX          (1)
#define QUEUE_EVENT       (2)
#define RX_BUFFERS_READY  (4)
#define RX_BUFFER_SIZE    (512)
#define EVENT_BUFFER_SIZE (128)

// Valid value for op-field
enum virtio_op {
	VIRTIO_VSOCK_OP_INVALID = 0,

	/* Connect operations */
	VIRTIO_VSOCK_OP_REQUEST = 1,
	VIRTIO_VSOCK_OP_RESPONSE = 2,
	VIRTIO_VSOCK_OP_RST = 3,
	VIRTIO_VSOCK_OP_SHUTDOWN = 4,

	/* To send payload */
	VIRTIO_VSOCK_OP_RW = 5,

	/* Tell the peer our credit info */
	VIRTIO_VSOCK_OP_CREDIT_UPDATE = 6,
	/* Request the peer to send the credit info to us */
	VIRTIO_VSOCK_OP_CREDIT_REQUEST = 7,
};

enum VSOCK_STATE {
	VSOCK_INVALID = 0,
	VSOCK_RESET,
	VSOCK_CLOSED,
	VSOCK_OPENED,
	VSOCK_TRY_ESTABLISH,
	VSOCK_LISTEN,
	VSOCK_CONNECTED,
	VSOCK_ESTABLISHED,
	VSOCK_WRITE_PENDING,
	VSOCK_READ_PENDING,
};


struct virtio_vsock_hdr {
	uint64_t src_cid;
	uint64_t dst_cid;
	uint32_t src_port;
	uint32_t dst_port;
	uint32_t len;
	uint16_t type;
	uint16_t op;
	uint32_t flags;
	uint32_t buf_alloc;
	uint32_t fwd_cnt;
} __attribute__((packed));

struct socket_conn {
	int state;
	uint32_t dst_cid, dst_port, src_port;
	uint32_t buf_alloc, fwd_cnt;
	ptr_t incoming;
	ptr_t outgoing;
};

struct vsock {
	uint32_t s_cid;
	uint32_t last_port;
	struct llist* opened;
};

struct vsock_job {
	enum JOB_TYPE type;
	void* uaddr;
	size_t len;
	enum VSOCK_STATE wakeup_when;
	int retval;
};
struct vsock_buffer {
	size_t size;
	void* buffer;
};
struct vsock_opened {
	mutex_t lock;
	enum VSOCK_STATE state;
	uint32_t t_cid, t_port, src_port;
	struct thread* owner;
	struct virtio_vsock_hdr* hdr;

	struct vsock_job job;

	struct XIFO* received;
};

#define VMADDR_CID_HYPERVISOR (0)
#define VMADDR_CID_HOST (2)

static struct vsock gvsock = {0};
//static struct socket_conn conn;
static struct virtio_dev_struct socketdev;

//static ptr_t ccid = 0;
static ptr_t read_guest_cid(struct virtio_dev_struct* dev)	{
	ptr_t ret;
	DMAR64(dev->base + VIRTIO_OFF_CONFIG, ret);
	logi("cid = %lx\n", ret);
	gvsock.s_cid = ret;
	return ret;
}
static int add_rx_buffers(struct virtio_dev_struct* dev)	{
	int i;
	for(i = 0; i < RX_BUFFERS_READY; i++)	{
		virtq_add_buffer(dev, RX_BUFFER_SIZE, VIRTQ_DESC_F_WRITE, QUEUE_RX, true, true);
	}
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, QUEUE_RX);
	return OK;
}


int socket_open(struct vfsopen* o, const char* file, int oflags, int omode)	{
	TZALLOC_ERR(ins, struct vsock_opened);

	ins->owner = current_thread();
	ins->state = VSOCK_OPENED;

	ins->received = xifo_alloc(4, 2);

	SET_VFS_DATA(o, ins);
	return o->fd;
}

static int _write_target(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, const void* buf, uint32_t len)	{
	ptr_t addr;
	int alen = len + sizeof(struct virtio_vsock_hdr);

	hdr->len = len;
	hdr->type = 1;

	addr = virtq_add_buffer(dev, alen, 0, QUEUE_TX, true, false);
	logi("WRITE Addr = %lx\n", addr);

	addr += cpu_linear_offset();
	
	memcpy((void*)addr, (void*)hdr, sizeof(struct virtio_vsock_hdr));
	if(!PTR_IS_ERR(buf))	{
		if(ADDR_USER(buf))	{
			memcpy_from_user((void*)(addr + sizeof(struct virtio_vsock_hdr)), buf, len);
		}
		else	{
			memcpy((void*)(addr + sizeof(struct virtio_vsock_hdr)), buf, len);
		}
	}
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, QUEUE_TX);
	return OK;
}

#define VSOCK_CID_MASK  ((1UL << 32) - 1)
#define VSOCK_PORT_MASK ((1UL << 32) - 1)
#define VSOCK_PACK_CID_PORT(cid,port) ((cid & VSOCK_CID_MASK) | ((port & VSOCK_PORT_MASK) << 32))

static int _connect_target(struct virtio_dev_struct* dev, struct vsock_opened* vsock)	{
	int res;
	if(vsock->state != VSOCK_OPENED)	return -USER_FAULT;
	if(!vsock->t_cid || !vsock->t_port)	return -USER_FAULT;

	TZALLOC_ERR(hdr, struct virtio_vsock_hdr);

	if(vsock->src_port == 0)	vsock->src_port = ++(gvsock.last_port);

	hdr->src_port = vsock->src_port;
	hdr->src_cid = gvsock.s_cid;
	hdr->dst_cid = vsock->t_cid;
	hdr->dst_port = vsock->t_port;
	hdr->buf_alloc = 0x40000;
	hdr->fwd_cnt = 0;

	hdr->op = VIRTIO_VSOCK_OP_REQUEST;

	vsock->hdr = hdr;
	vsock->state = VSOCK_TRY_ESTABLISH;
	
	llist_insert(gvsock.opened, vsock, VSOCK_PACK_CID_PORT(hdr->src_cid, hdr->src_port));
	
	res = _write_target(dev, vsock->hdr, NULL, 0);

	// Sleep until connection is established
	if(res == OK)	{
		vsock->job.type = JOB_FCNTL;
		vsock->job.retval = OK;
		vsock->job.wakeup_when = VSOCK_ESTABLISHED;
		return -BLOCK_THREAD;
	}
	return res;
}
static int _listen(struct virtio_dev_struct* dev, struct vsock_opened* vsock)	{
	//int res = OK;
	if(vsock->src_port == 0)	return -USER_FAULT;
	TZALLOC_ERR(hdr, struct virtio_vsock_hdr);
	//ptr_t recv;

	hdr->src_port = vsock->src_port;
	hdr->src_cid = gvsock.s_cid;
	hdr->dst_cid = 0;
	hdr->dst_port = 0;
	hdr->buf_alloc = 0x40000;
	hdr->fwd_cnt = 0;

	vsock->hdr = hdr;
	llist_insert(gvsock.opened, vsock, VSOCK_PACK_CID_PORT(vsock->hdr->src_cid, vsock->hdr->src_port));

	vsock->state = VSOCK_LISTEN;
	vsock->job.type = JOB_FCNTL;
	vsock->job.retval = OK;
	vsock->job.wakeup_when = VSOCK_ESTABLISHED;
	return -BLOCK_THREAD;
}


int socket_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	GET_VFS_DATA(o, struct vsock_opened, vsock);
	mutex_acquire(&vsock->lock);
	switch(cmd)	{
	case FCNTL_VIRTIO_SET_CID:
		vsock->t_cid = (arg & VSOCK_CID_MASK);
		break;
	case FCNTL_VIRTIO_SET_DST_PORT:
		vsock->t_port = (arg & VSOCK_PORT_MASK);
		break;
	case FCNTL_VIRTIO_SET_TARGET:
		vsock->t_cid = (arg & VSOCK_CID_MASK);
		arg >>= 32;
		vsock->t_port = (arg & VSOCK_PORT_MASK);
		break;
	case FCNTL_VIRTIO_CONNECT:
		res = _connect_target(&socketdev, vsock);
		break;
	case FCNTL_VIRTIO_LISTEN:
		res = _listen(&socketdev, vsock);
		break;
	case FCNTL_VIRTIO_SET_SRC_PORT:
		vsock->src_port = (arg & VSOCK_PORT_MASK);
		break;
	default:
		res = -USER_FAULT;
		break;

	}
	mutex_release(&vsock->lock);
	return res;
}
int socket_read(struct vfsopen* o, void* buf, size_t sz)	{
	int res = OK;
	GET_VFS_DATA(o, struct vsock_opened, vsock);
	logi("socket read\n");

	mutex_acquire(&vsock->lock);

	if(vsock->state != VSOCK_ESTABLISHED)	{
		logw("Tried to write to unready vsock: %i\n", vsock->state);
		res = -USER_FAULT;
		goto err1;
	}

	struct vsock_buffer* _buf = NULL;
	if((_buf = xifo_pop_front(vsock->received)) != NULL)	{
		res = MIN(sz, _buf->size);
		mmu_memcpy(thread_get_user_pgd(vsock->owner), buf, _buf->buffer, res);

		// User might not read whole input
		if((size_t)res < _buf->size)	{
			_buf->buffer += res;
			_buf->size -= res;
			xifo_push_front(vsock->received, (void*)_buf);
		}
		else	{
			kfree(_buf);
		}

	}
	else	{
		// Need to store all the data so that we can wakeup the thread when
		// we do receive some data
		vsock->state = VSOCK_READ_PENDING;
		vsock->job.type = JOB_READ;
		vsock->job.uaddr = buf;
		vsock->job.len = sz;
		vsock->job.wakeup_when = VSOCK_ESTABLISHED;

		res = -BLOCK_THREAD;
	}
err1:
	mutex_release(&vsock->lock);
	return res;
}
int socket_close(struct vfsopen* o)	{
	int res;
	GET_VFS_DATA(o, struct vsock_opened, vsock);
	logi("socket close\n");

	if(vsock->state > VSOCK_OPENED)	{
		vsock->hdr->op = VIRTIO_VSOCK_OP_SHUTDOWN;
		vsock->hdr->flags |= 3;
	}
	res = _write_target(&socketdev, vsock->hdr, NULL, 0);
	return res;
}

int socket_write(struct vfsopen* o, const void* buf, size_t sz)	{
	int res;
	GET_VFS_DATA(o, struct vsock_opened, vsock);
	logi("socket write\n");
	if(sz > INT_MAX)	return -USER_FAULT;

	mutex_acquire(&vsock->lock);

	if(vsock->state != VSOCK_ESTABLISHED)	{
		logw("Tried to write to unready vsock: %i\n", vsock->state);
		res = -USER_FAULT;
		goto err1;
	}

	vsock->hdr->op = VIRTIO_VSOCK_OP_RW;
	res = _write_target(&socketdev, vsock->hdr, buf, (int)sz);
	//if(res == OK)	res = sz;

	// We don't block on write since there is no confirmation of packet received
	
	if(res == OK)	{
		res = -BLOCK_THREAD;

		// Mutex ensures that IRQ is not processed before these values are set
		vsock->state = VSOCK_WRITE_PENDING;
		vsock->job.type = JOB_WRITE;
		vsock->job.wakeup_when = VSOCK_ESTABLISHED;
		vsock->job.retval = sz;
	}
		
err1:
	mutex_release(&vsock->lock);
	return res;
}


static struct fs_struct virtiosocketdev = {
	.name = "socket",
	.open  = socket_open,
	.read  = socket_read,
	.fcntl = socket_fcntl,
	.write = socket_write,
	.close = socket_close,
	.perm = ACL_PERM(ACL_READ|ACL_WRITE|ACL_CTRL, ACL_READ|ACL_WRITE|ACL_CTRL, ACL_NONE),
};

static int __handle_try_establish(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, struct vsock_opened* vsock)	{
	if(hdr->op == VIRTIO_VSOCK_OP_RESPONSE)	{
		vsock->state = VSOCK_ESTABLISHED;

		// Try and ask for credit info
//		vsock->hdr->op = VIRTIO_VSOCK_OP_CREDIT_REQUEST;
		return OK;
//		return _write_target(dev, vsock->hdr, NULL, 0);
	}
	else if(hdr->op == VIRTIO_VSOCK_OP_RST)	{
		logw("Tried to connect to non-existent target\n");
		vsock->state = VSOCK_RESET;
		return -USER_FAULT;
	}

	vsock->state = VSOCK_CLOSED;
	logw("Receieved unexpected response from target: %i\n", hdr->op);
	return -GENERAL_FAULT;
}
static int __handle_connected(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, struct vsock_opened* vsock)	{
	// TODO: Check what op should be
//	vsock->hdr->buf_alloc = hdr->buf_alloc;
//	vsock->hdr->fwd_cnt = hdr->fwd_cnt;
	vsock->state = VSOCK_ESTABLISHED;
	//_thread_wakeup(vsock->owner->id, OK);
	return OK;
}
static int __handle_write(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, struct vsock_opened* vsock)	{
	// TODO: Check what op should be
	
	vsock->job.type = JOB_NONE;
	vsock->state = VSOCK_ESTABLISHED;
	return OK;
}

static int __store_buffer(struct vsock_opened* vsock, void* buf, size_t len)	{
	TZALLOC_ERR(ins, struct vsock_buffer);
	logw("TODO: Storing input in buffer which may be overwritten by next scheduled job\n");
	ins->size = len;
	ins->buffer = buf;
	xifo_push_back(vsock->received, ins);
	return OK;
}

static int __handle_request(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, struct vsock_opened* vsock)	{
	int res = -GENERAL_FAULT;
	if(vsock->state == VSOCK_LISTEN)	{
		vsock->hdr->dst_cid = hdr->src_cid;
		vsock->hdr->dst_port = hdr->src_port;
		vsock->hdr->op = VIRTIO_VSOCK_OP_RESPONSE;
		_write_target(dev, vsock->hdr, NULL, 0);

		logw("Setting state before confirmation on packet receipt\n");
		vsock->state = VSOCK_ESTABLISHED;
		res = OK;
	}
	return OK;
}

static int __handle_incoming(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, struct vsock_opened* vsock, size_t len)	{
	int res = -GENERAL_FAULT;
	size_t tocopy = len;
	void* incoming = (void*)hdr;
	incoming += sizeof(struct virtio_vsock_hdr);
	if(tocopy > 0 && hdr->op == VIRTIO_VSOCK_OP_RW)	{
		if(vsock->state == VSOCK_READ_PENDING && tocopy > 0)	{
			size_t tocopy = MIN(vsock->job.len, len);
			vsock->job.retval = tocopy;
			vsock->job.type = JOB_NONE;
			vsock->state = VSOCK_ESTABLISHED;
			mmu_memcpy(thread_get_user_pgd(vsock->owner), vsock->job.uaddr, incoming, tocopy);
			incoming += tocopy;
			len -= tocopy;
			res = OK;
		}

		// If there is any more data, we must store it
		if(len > 0)	{
			__store_buffer(vsock, incoming, len);
		}
		res = OK;
	}
	return res;
}
static int __handle_reset(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, struct vsock_opened* vsock)	{
	int res = OK;

	// Must check if the reset happens when we are connecting
	switch(vsock->state)	{
	case VSOCK_TRY_ESTABLISH:
	case VSOCK_CONNECTED:
		res = -GENERAL_FAULT;
		break;
	default:
		res = -GENERAL_FAULT;
		break;
	}

	vsock->state = VSOCK_RESET;
	return res;
}
static int __handle_response(struct virtio_dev_struct* dev, struct virtio_vsock_hdr* hdr, struct vsock_opened* vsock)	{
	int res = OK;
	switch(vsock->state)	{
	case VSOCK_TRY_ESTABLISH:
		res = __handle_try_establish(dev, hdr, vsock);
		break;
	case VSOCK_CONNECTED:
		res = __handle_connected(dev, hdr, vsock);
		break;
	case VSOCK_WRITE_PENDING:
		res = __handle_write(dev, hdr, vsock);
		break;
	default:
		res = -1;
		break;
	}
	return res;
}

static int _handle_incoming(struct virtq_desc* desc, struct virtq_used_elem* elem)	{
	logi("Handle incoming\n");
	struct virtio_dev_struct* dev = &socketdev;
	if(elem->len < sizeof(struct virtio_vsock_hdr))	{
		logw("Packet received is not large enough: %i\n", elem->len);
		return -1;
	}
	struct virtio_vsock_hdr* hdr = (struct virtio_vsock_hdr*)(desc->paddr + cpu_linear_offset());
	ptr_t key = VSOCK_PACK_CID_PORT(hdr->dst_cid, hdr->dst_port);

	struct vsock_opened* vsock = llist_find(gvsock.opened, key);
	if(PTR_IS_ERR(vsock))	return PTR_TO_ERRNO(vsock);

	// If we have gotten this far, we have a thread we need to do some work on
	mutex_acquire(&vsock->lock);

	// I think we only need to update this if we need to keep the buffer
	//vsock->hdr->fwd_cnt += elem->len;

	int res = OK;
	switch(hdr->op)	{
	case VIRTIO_VSOCK_OP_REQUEST:
		res = __handle_request(dev, hdr, vsock);
		break;
	case VIRTIO_VSOCK_OP_RESPONSE:
		logi("OP_RESP\n");
		res = __handle_response(dev, hdr, vsock);
		break;
	case VIRTIO_VSOCK_OP_RST:
		res = __handle_reset(dev, hdr, vsock);
		break;
	case VIRTIO_VSOCK_OP_SHUTDOWN:
		vsock->state = VSOCK_CLOSED;
		break;
	case VIRTIO_VSOCK_OP_RW:
		res = __handle_incoming(dev, hdr, vsock, elem->len - sizeof(struct virtio_vsock_hdr));
		break;
	case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
		PANIC("Must send credit response\n");
		break;
	case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
		PANIC("Must send credit response\n");
		break;
	default:
		// TODO: Need to send a RST packet in response
		// A VIRTIO_VSOCK_OP_RST reply MUST be sent if a packet is received with an unknown type value
		res = -GENERAL_FAULT;
		break;
	}
	/*

	// We might hit this in a couple of cases:
	// 1. It's a normal read-job
	// 2. We received data unexpectedly (before used asked for it)
	// 3. We reveieved data before completing some other steps
	// 4. We received unexpected data from peer
	//    - This is the only error-scenario
	if(res < 0)	{
		res = __handle_incoming(dev, hdr, vsock, len - sizeof(struct virtio_vsock_hdr));
	}*/

	if(res < 0)	{
		logw("Unable to handle incoming data from peer %i:%i - %i\n", hdr->src_cid, hdr->src_port, elem->len);
	}

	// Wakeup thread if we've reached desired state
	if(vsock->state == vsock->job.wakeup_when)	{
		vsock->job.wakeup_when = VSOCK_INVALID;
		thread_wakeup(vsock->owner->id, vsock->job.retval);
	}
	// We also wake up thread if an error happened and thread is waiting
	else if(res < 0 && vsock->job.wakeup_when != VSOCK_INVALID)	{
		vsock->job.wakeup_when = VSOCK_INVALID;
		vsock->state = VSOCK_CLOSED;
		thread_wakeup(vsock->owner->id, res);
	}
	mutex_release(&vsock->lock);
	return res;
}


int virtio_socket_irq_cb(int irqno)	{
	logi("IRQ socket\n");
	int res, idx;
	struct virtio_dev_struct* dev = &socketdev;
	struct virtq_used* u = virtq_get_used(dev, 0);
	//struct virtq_used* _u = virtq_get_used(dev, 2);
	idx = u->idx - 1;
	struct virtq_used_elem* elem = &(u->used[idx]);
	struct virtq_desc* desc = virtio_get_desc(dev, 0, elem->idx);


	res = virtio_intr_status(dev);
	logi("res = %x | idx = %i | paddr = %lx\n", res, idx, desc->paddr);
	virtio_ack_intr(dev);
	if(FLAG_SET(res, VIRTIO_INTR_STATUS_RING_UPDATE))	{
		_handle_incoming(desc, elem);
	}
	else if(res == 0)	{
		if(idx + RX_BUFFERS_READY > dev->virtq->queues[QUEUE_RX].idx)	{
			logi("Creating new buffer job for input\n");
			add_rx_buffers(dev);
//			ptr_t va = virtq_add_buffer(dev, RX_BUFFER_SIZE, VIRTQ_DESC_F_WRITE, QUEUE_RX, true, false);
//			logi("va = %lx\n", va);
		}
//		DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, QUEUE_RX);
	}
	return OK;
}

int virtio_socket_init(struct virtio_dev_struct* dev)	{
	int res;
	virtio_generic_init(dev, VIRTIO_F_GENERIC_SUPPORTED);

	read_guest_cid(dev);

	res = virtq_create_alloc(dev, SOCKET_QSZ, NUM_PAGES, NUM_QUEUES);
	ASSERT_TRUE(res == OK, "error");

	res = virtq_add_queue(dev, 0); 
	ASSERT_TRUE(res == OK, "error");
	res = virtq_add_queue(dev, 1); 
	ASSERT_TRUE(res == OK, "error");
	res = virtq_add_queue(dev, 2); 
	ASSERT_TRUE(res == OK, "error");

	res = virtio_virtq_init(dev);
	ASSERT_TRUE(res == OK, "error");

	res = virtio_complete_init(dev);
	ASSERT_TRUE(res == OK, "error");

	dev->irqno += gic_spi_offset();
	gic_set_priority(dev->irqno, 1);
	gic_clear_intr(dev->irqno);
	gic_enable_intr(dev->irqno);
	gic_register_cb(dev->irqno, virtio_socket_irq_cb);

	memcpy(&socketdev, dev, sizeof(struct virtio_dev_struct));

	add_rx_buffers(&socketdev);
	
	//for(i = 0; i < RX_BUFFERS_READY; i++)	{
	//	virtq_add_buffer(dev, RX_BUFFER_SIZE, VIRTQ_DESC_F_WRITE, QUEUE_RX, true, false);
	//}
	//DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, QUEUE_RX);
	

	virtq_add_buffer(dev, EVENT_BUFFER_SIZE, VIRTQ_DESC_F_WRITE, QUEUE_EVENT, true, false);
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, QUEUE_EVENT);

	gvsock.last_port = 1024;
	gvsock.opened = llist_alloc();

	device_register( &virtiosocketdev );
	return OK;
}

int virtio_socket_register(void)   {
	virtio_register_cb(SOCKET, virtio_socket_init);
	return OK;
}
early_hw_init(virtio_socket_register);

int virtio_socket_exit(void)	{
	if(PTR_IS_VALID(gvsock.opened))	{
		kfree(gvsock.opened);
	}
	return virtq_destroy_alloc(&socketdev);
}
poweroff_exit(virtio_socket_exit);
