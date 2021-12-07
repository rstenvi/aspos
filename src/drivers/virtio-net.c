/**
* Virt I/O network device
*/

#include "kernel.h"
#include "virtio.h"
#include "vfs.h"

#define VIRTIO_NET_F_CSUM                (1<<0)
#define VIRTIO_NET_F_GUEST_CSUM          (1<<1)
#define VIRTIO_NET_F_CTRL_GUEST_OFFLOADS (1<<2)
#define VIRTIO_NET_F_MAC                 (1<<5)
#define VIRTIO_NET_F_GUEST_TSO4          (1<<7)
#define VIRTIO_NET_F_GUEST_TSO6          (1<<8)
#define VIRTIO_NET_F_GUEST_ECN           (1<<9)
#define VIRTIO_NET_F_GUEST_UFO           (1<<10)
#define VIRTIO_NET_F_HOST_TSO4           (1<<11)
#define VIRTIO_NET_F_HOST_TSO6           (1<<12)
#define VIRTIO_NET_F_HOST_ECN            (1<<13)
#define VIRTIO_NET_F_HOST_UFO            (1<<14)
#define VIRTIO_NET_F_MRG_RXBUF           (1<<15)
#define VIRTIO_NET_F_STATUS              (1<<16)
#define VIRTIO_NET_F_CTRL_VQ             (1<<17)
#define VIRTIO_NET_F_CTRL_RX             (1<<18)
#define VIRTIO_NET_F_CTRL_VLAN           (1<<19)
#define VIRTIO_NET_F_GUEST_ANNOUNCE      (1<<21)
#define VIRTIO_NET_F_MQ                  (1<<22)
#define VIRTIO_NET_F_CTRL_MAC_ADDR       (1<<23)

#define VIRTIO_NET_F_SUPPORTED \
	(VIRTIO_NET_F_CSUM | VIRTIO_NET_F_MAC | VIRTIO_NET_F_GUEST_CSUM)

#define VIRTQ_NET_BUFFER_PAGES (1)

#define VRTIO_RNG_NUM_BUFS (225)

struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM    1
	uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE        0
#define VIRTIO_NET_HDR_GSO_TCPV4       1
#define VIRTIO_NET_HDR_GSO_UDP         3
#define VIRTIO_NET_HDR_GSO_TCPV6       4
#define VIRTIO_NET_HDR_GSO_ECN      0x80
	uint8_t gso_type;
	uint16_t hdr_len;
	uint16_t gso_size;
	uint16_t csum_start;
	uint16_t csum_offset;

	/* The legacy driver only presented num_buffers in the struct virtio_net_hdr
	 * when VIRTIO_NET_F_MRG_RXBUF was negotiated; without that feature the
	 * structure was 2 bytes shorter
	 */
//	uint16_t num_buffers;
} __attribute__((packed));


#define NETDEV_MAX_PACKETS 16

struct netdev_packet {
	void* data;
	size_t len;
};

struct netdev_packets {
	int curridx, lastidx;
	struct netdev_packet packet[NETDEV_MAX_PACKETS];
};

struct netdev_job {
	struct vfsopen* opened;
	enum JOB_TYPE type;
	void* uaddr;
	size_t sz;
	int tid;
};

struct netdev_status {
	void* recvbuffer;
	struct netdev_packets pkts;
	struct netdev_job job;
};


static struct netdev_status status;
static struct virtio_dev_struct netdev;





int lastlen = 0;

static int _net_new_incoming(void* buf, size_t sz);
static int netdev_check_wakeup(void);

static int virtio_net_irq_cb(int irqno)	{
	struct virtio_dev_struct* dev = &netdev;
	int res;

	logd("Received IRQ on net\n");

	struct virtq_used* u = virtq_get_used(dev, 0);

	void* buf = (void*)(status.recvbuffer + sizeof(struct virtio_net_hdr));

	res = virtio_intr_status(dev);
	if(FLAG_SET(res, VIRTIO_INTR_STATUS_RING_UPDATE))	{
		_net_new_incoming(buf, u->used[0].len);
	}

	virtio_ack_intr(dev);
	// Check if any thread is waiting for data
	netdev_check_wakeup();
	return res;
}

static int _net_read_existing_pkt(struct vfsopen* o, void* buf, size_t sz)	{
	struct netdev_packet* pkt = &(status.pkts.packet[status.pkts.curridx]);
	size_t rlen;
	
	rlen = MIN(sz, pkt->len);
	memcpy(buf, pkt->data, rlen);

	// We might be finished with packet or there might be more left
	if(rlen == pkt->len)	{
		status.pkts.curridx = (status.pkts.curridx + 1) % NETDEV_MAX_PACKETS;
	}
	else	{
		pkt->data += rlen;
		pkt->len -= rlen;
	}
	return rlen;
}

static int _net_read_existing(struct vfsopen* o, void* buf, size_t sz)	{
	// TODO: Maybe read multiple packets
	return _net_read_existing_pkt(o, buf, sz);
}

int net_read(struct vfsopen* o, void* buf, size_t sz)	{
	if(status.pkts.curridx != status.pkts.lastidx)	{
		return _net_read_existing(o, buf, sz);
	}

	// There is no data to read yet, we mark it as a job
	status.job.type = JOB_READ;
	status.job.opened = o;
	status.job.uaddr = buf;
	status.job.sz = sz;
	status.job.tid = current_tid();
	return -BLOCK_THREAD;
}

static int netdev_check_wakeup(void)	{
	struct netdev_job* j = &(status.job);
	if(j->type == JOB_READ && status.pkts.curridx != status.pkts.lastidx)	{
		size_t ret = _net_read_existing(j->opened, j->uaddr, j->sz);
		j->type = JOB_NONE;
		thread_wakeup(j->tid, ret);
	}
	return OK;
}

static int _net_new_incoming(void* buf, size_t sz)	{
//	struct netdev_job* j = &(status.job);
	int i = status.pkts.lastidx;
	status.pkts.packet[i].data = buf;
	status.pkts.packet[i].len = sz;

	status.pkts.lastidx = (status.pkts.lastidx + 1) % NETDEV_MAX_PACKETS;
	if(status.pkts.lastidx == status.pkts.curridx)	{
		// To keep the indexes sane we must always leave one space available
		// so, when we have NETDEV_MAX_PACKETS - 1 packets, we are full
		status.pkts.curridx = (status.pkts.curridx + 1) % NETDEV_MAX_PACKETS;
		logw("Incoming packet buffer is full, will overwrite old packet\n");
	}

	return OK;
}

int net_write(struct vfsopen* o, const void* buf, size_t sz)	{
//	int res;
	struct virtio_dev_struct* dev = &netdev;
	ptr_t addr;
	struct virtio_net_hdr* data;
	void* copy;

	addr = virtq_add_buffer(dev, sz + sizeof(struct virtio_net_hdr), 0, 1, true, false);
	data = (struct virtio_net_hdr*)(cpu_linear_offset() + addr);


	data->flags = 0;
	data->gso_type = VIRTIO_NET_HDR_GSO_NONE;
	data->hdr_len = sz - 4;
	data->gso_size = 0;
	data->csum_start = 0;
	data->csum_offset = 0;

	// Buffer to write is directly after header
	copy = (void*)(cpu_linear_offset() + addr + sizeof(struct virtio_net_hdr));

	memcpy(copy, buf, sz);

	// TODO: We should have several buffers already lined up
	addr = virtq_add_buffer(dev, 2048, VIRTQ_DESC_F_WRITE, 0, true, false);
	status.recvbuffer = (void*)(addr + cpu_linear_offset());


	// Notify the device
	DMAW32(dev->base + VIRTIO_OFF_QUEUE_NOTIFY, 1);

	// We don't block here
	// We treat packet as immediately sent and they need to call read to
	// retrieve packet
	return sz;
}

static struct fs_struct virtionetdev = {
	.name = "ethernet",
	.read = net_read,
	.write = net_write,
	.perm = DRIVER_DEFAULT_PERM,
};

static void read_mac(struct virtio_dev_struct* dev, unsigned char* output)	{
	int i;
	for(i = 0; i < 6; i++)	{
		DMAR8(dev->base + VIRTIO_OFF_CONFIG + i, output[i]);
	}
	logi("MAC: %x:%x:%x:%x:%x:%x\n", output[0], output[1], output[2],
		output[3], output[4], output[5]
	);
}

int virtio_net_init(struct virtio_dev_struct* dev)	{
//	unsigned char mac[6] = {0};
	int res;

	res = virtio_generic_init(dev, VIRTIO_NET_F_SUPPORTED);
	ASSERT_TRUE(res == OK, "error");

	read_mac(dev, osdata.network.mac);

	res = virtq_create_alloc(dev, VRTIO_RNG_NUM_BUFS, 4, 2);
	ASSERT_TRUE(res == OK, "error");

	res = virtq_add_queue(dev, 0);
	ASSERT_TRUE(res == OK, "error");
	res = virtq_add_queue(dev, 1);
	ASSERT_TRUE(res == OK, "error");

	res = virtio_virtq_init(dev);
	ASSERT_TRUE(res == OK, "error");
	
	res = virtio_complete_init(dev);
	ASSERT_TRUE(res == OK, "error");


	dev->irqno += gic_spi_offset();
	gic_set_priority(dev->irqno, 1);
	gic_clear_intr(dev->irqno);
	gic_enable_intr(dev->irqno);
	gic_register_cb(dev->irqno, virtio_net_irq_cb);

	memcpy(&netdev, dev, sizeof(struct virtio_dev_struct));

	memset(&status, 0x00, sizeof(struct netdev_status));

	device_register( &virtionetdev );
	return OK;
}

int virtio_net_register(void)	{
	virtio_register_cb(NETWORK_CARD, virtio_net_init);
	return OK;
}
early_hw_init(virtio_net_register);

int virtio_net_exit(void)    {
    virtq_destroy_alloc(&netdev);
	return 0;
}
poweroff_exit(virtio_net_exit);
