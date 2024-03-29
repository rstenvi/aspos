#include "kernel.h"

#define PL011_OFF_UARTDR    0x000
#define PL011_OFF_UARTRSR   0x004
#define PL011_OFF_UARTECR   0x004
#define PL011_OFF_UARTFR    0x018
#define PL011_OFF_UARTILPR  0x020
#define PL011_OFF_UARTIBRD  0x024
#define PL011_OFF_UARTFBRD  0x028
#define PL011_OFF_UARTLCR_H 0x02c
#define PL011_OFF_UARTCR    0x030
#define PL011_OFF_UARTIFLS  0x034
#define PL011_OFF_UARTIMSC  0x038
#define PL011_OFF_UARTRIS   0x03c
#define PL011_OFF_UARTMIS   0x040
#define PL011_OFF_UARTICR   0x044
#define PL011_OFF_UARTDMACR 0x048

#define ONE_OVER_EIGHT   (0b000)
#define ONE_OVER_FOUR    (0b001)
#define ONE_OVER_TWO     (0b010)
#define THREE_OVER_FOUR  (0b011)
#define SEVEN_OVER_EIGHT (0b100)

#define UARTIFLS_TXIFLSEL_EIGHT 0b000


#define UARTIFLS_RXIFLSEL_EIGHT (0b000 << 3)

#define UART_RXIFLSEL (SEVEN_OVER_EIGHT << 3)
#define UART_TXIFLSEL (SEVEN_OVER_EIGHT)

#define PL011_OFF_UARTPeriphID0 0xFE0
#define PL011_OFF_UARTPeriphID1 0xFE4
#define PL011_OFF_UARTPeriphID2 0xFE8
#define PL011_OFF_UARTPeriphID3 0xFEC
#define PL011_OFF_UARTPCellID0  0xFF0
#define PL011_OFF_UARTPCellID1  0xFF4
#define PL011_OFF_UARTPCellID2  0xFF8
#define PL011_OFF_UARTPCellID3  0xFFC


// transmit/receive line register flags
#define PL011_LCRH_SPS    (1 << 7)
#define PL011_LCRH_WLEN_8 (3 << 5)
#define PL011_LCRH_WLEN_7 (2 << 5)
#define PL011_LCRH_WLEN_6 (1 << 5)
#define PL011_LCRH_WLEN_5 (0 << 5)
#define PL011_LCRH_FEN    (1 << 4)
#define PL011_LCRH_STP2   (1 << 3)
#define PL011_LCRH_EPS    (1 << 2)
#define PL011_LCRH_PEN    (1 << 1)
#define PL011_LCRH_BRK    (1 << 0)

// control register flags
#define PL011_CR_CTSEN    (1 << 15)
#define PL011_CR_RTSEN    (1 << 14)
#define PL011_CR_OUT2     (1 << 13)
#define PL011_CR_OUT1     (1 << 12)
#define PL011_CR_RTS      (1 << 11)
#define PL011_CR_DTR      (1 << 10)
#define PL011_CR_RXE      (1 << 9)
#define PL011_CR_TXE      (1 << 8)
#define PL011_CR_LPE      (1 << 7)
#define PL011_CR_OVSFACT  (1 << 3)
#define PL011_CR_SIREN    (1 << 1)
#define PL011_CR_UARTEN   (1 << 0)



#define PL011_IMSC_RTIM  (1 << 6)
#define PL011_IMSC_TXIM  (1 << 5)
#define PL011_IMSC_RXIM  (1 << 4)

#define UART_FR_RXFE (1 << 4)

#define UART_DATA_BUF_SZ (4096 * 4)

struct uart_read {
	void* uaddr;
	size_t max;
	struct thread* thread;
};

struct uart_struct {
	mutex_t lock;
	ptr_t base;

	// Buffer we maintain
	uint8_t* data;
	size_t maxdata;
	size_t firstidx, curridx;

	enum CHARDEV_MODE mode;

	struct uart_read job;

	struct XIFO* write_pending;
};

static struct uart_struct uart;

#define UART_BASE 0x09000000


#define TMP_CLOCKFREQ 0x16e3600
#define TMP_BAUD      115200

static mutex_t uartlock = 0;

__no_asan static bool poll_have_rx_data()	{
	uint32_t r = 0;
	DMAR32(uart.base + PL011_OFF_UARTFR, r);
	return !(r & UART_FR_RXFE);
}

#if defined(CONFIG_EARLY_UART)
static int _init_pl011(ptr_t base, uint32_t baud, uint32_t clk);

__no_asan int uart_early_putc(char c)	{
	DMAW32(uart.base, (uint32_t)c);
	return OK;
}

__no_asan int uart_early_getc(void)	{
	uint32_t r = 0;
	while(!poll_have_rx_data()) ;
	DMAR32(uart.base, r);
	return (r & 0xff);
}


__no_asan int uart_early_write(const char* str)	{
	int count = 0;
	mutex_acquire(&uartlock);
	while(*str != 0x00)	{
		uart_early_putc(*str++);
		count += 1;
	}
	mutex_release(&uartlock);
	return count;
}
#endif

int uart_early_init()	{
	uart.base = UART_BASE;
	mutex_clear(&uartlock);
	return 0;
}
static void pl011_flush(ptr_t base)	{
	// TODO: Implement
}

static int _init_pl011(ptr_t base, uint32_t baud, uint32_t clk)	{
	// Clear anny errors
	DMAW32(base + PL011_OFF_UARTRSR, 0);

	// Clear configuration
	DMAW32(base + PL011_OFF_UARTCR, 0);

	ASSERT_TRUE(baud > 0, "Baud is invalid\n");
	uint32_t div = (clk / (16 * baud));
	double rem = ((double)clk / (16 * baud)) - div;
	rem *= 64;
	rem += 0.5;
	uint32_t frac = (uint32_t)rem;
	DMAW32(base + PL011_OFF_UARTIBRD, div);
	DMAW32(base + PL011_OFF_UARTFBRD, frac);

	
	div = (clk * 4) / baud;

	// Integer baud register
	DMAW32(base + PL011_OFF_UARTIBRD, (div >> 6));

	// Fractional baud register
	DMAW32(base + PL011_OFF_UARTFBRD, (div & 0x3f));


	// Clear all interrupts
	DMAW32(base + PL011_OFF_UARTICR, ((1<<11)-1));

	DMAW32(base + PL011_OFF_UARTDMACR, 1|2|4);

	// Write to PL011_OFF_UARTLCR_H MUST come after IBRD and FBRD
	// TX = 8 bits, 1 stop bit, no parity, fifo
	DMAW32(base + PL011_OFF_UARTLCR_H, PL011_LCRH_WLEN_8 | PL011_LCRH_FEN);

	// Enable interrupts for receive, transmit and receive timeout
	DMAW32(base + PL011_OFF_UARTIMSC, /*((1<<11)-1)*/(PL011_IMSC_RXIM | /*PL011_IMSC_TXIM |*/ PL011_IMSC_RTIM));


	DMAW32(base + PL011_OFF_UARTIFLS, (UART_RXIFLSEL | UART_TXIFLSEL));

	// Enable UART
	DMAW32(base + PL011_OFF_UARTCR,
		(PL011_CR_UARTEN | PL011_CR_SIREN | PL011_CR_TXE | PL011_CR_RXE));


	pl011_flush(base);
	return 0;
}

// static int _check_read_job()	{
// }
//int pl011_open(struct vfsopen* o, void* buf, int count)	{


static int check_wakeup_read(void)	{
	// Check if we have any data to send
	if(uart.curridx <= 0 || uart.firstidx == uart.curridx)	return OK;

	// Check if anyone wants data
	struct thread* t = uart.job.thread;
	if(PTR_IS_ERR(t))	return OK;
//	if(t->id < 0)	return OK;

	char last = uart.data[uart.curridx-1];
	int ret = OK;

	if((uart.mode == CHAR_MODE_LINE || uart.mode == CHAR_MODE_LINE_ECHO) && last == '\n')	{
		ret = USER_WAKEUP;
	}
	else if(uart.mode == CHAR_MODE_BYTE)	{
		ret = USER_WAKEUP;
	}
	else if( (uart.curridx - uart.firstidx) >= uart.job.max)	{
		ret = USER_WAKEUP;
	}
	
	// If we get here, we should not return to user-mode
	return ret;
}

static int perform_read_job(int* res)	{
	if(PTR_IS_ERR(uart.job.thread))	return OK;

	int tid = uart.job.thread->id;
	size_t dataread = (uart.curridx - uart.firstidx);
	size_t doread = MIN(uart.job.max, dataread);
	*res = doread;
	if(uart.mode != CHAR_MODE_BYTE)	{
		mmu_memcpy(thread_get_user_pgd(uart.job.thread), uart.job.uaddr, &(uart.data[uart.firstidx]), doread);
		if(dataread > doread)	{
			//logd("memmove %i, %i, %i\n", uart.firstidx, uart.firstidx + doread, dataread - doread);
			memmove(&uart.data[uart.firstidx], &uart.data[uart.firstidx + doread], dataread - doread);
			uart.curridx -= doread;
		}
		else	{
			uart.curridx = uart.firstidx = 0;
		}
	}
	else	{
		*res = uart.data[uart.firstidx++];
	}
	uart.job.thread = NULL;
	return tid;
}

int pl011_read(struct vfsopen* o, void* buf, size_t count)	{
	uart.job.thread = current_thread();
	uart.job.uaddr = buf;
	uart.job.max = count;

	int res = check_wakeup_read();
	if(res == USER_WAKEUP)	{
		int uret = 0;
		perform_read_job(&uret);
		return uret;
	}
	return -BLOCK_THREAD;
}

int pl011_getc(struct vfsopen* o)	{
	int res;
	uart.mode = CHAR_MODE_BYTE;
	uart.job.thread = current_thread();
	uart.job.uaddr = NULL;
	uart.job.max = 0;

	res = check_wakeup_read();
	if(res == USER_WAKEUP)	{
		int uret = 0;
		perform_read_job(&uret);
		return OK;
	}
	return -BLOCK_THREAD;
}

int pl011_putc(struct vfsopen* o, int c)	{
	c &= 0xff;
	// No need for lock here, access is atomic
	DMAW32(uart.base, (uint32_t)(c));
	return (int)c;
}
void _write_string(char* buf)	{
	int l = strlen(buf), i;
	for(i = 0; i < l; i++)	{
		DMAW32(uart.base, (uint32_t)(buf[i]));
	}
}
void _try_write_pending(void)	{
	if(uart.write_pending == NULL)	return;
	char* buf;
	while( (buf = xifo_pop_front(uart.write_pending)) != NULL)	{
		_write_string(buf);
		kfree(buf);
	}
}
__no_asan int _shared_write(char* buf, size_t count, bool kernel)	{
	int res = OK;
	size_t i;

	// We might write to this log from an error condition which resulted from a
	// print. To avoid a deadlock in these instances, we only try and acquire
	// the lock. If we can't get it, we add the buffer to a queue and try and
	// write it afterwardsy.
//	res = mutex_try_acquire(&uartlock);
	if(res == OK)	{
		for(i = 0; i < count; i++)	{
			DMAW32(uart.base, (uint32_t)(buf[i]));
		}
	}
	return res;
}
int kern_write(const char* buf, size_t count)	{
	int res = -1;
	mutex_acquire(&uartlock);
	res = _shared_write((char*)buf, count, true);
	mutex_release(&uartlock);
	return res;
}
#define BUF_STACK_MAX (256)
int pl011_write(struct vfsopen* o, const void* buf, size_t count)	{
	int ret = 0;
	size_t currc;
	char arr[BUF_STACK_MAX];
	ASSERT(ADDR_USER(buf));

	mutex_acquire(&uartlock);
	//arr = (char*)kmalloc(count + 1);
	while(count > 0)	{
		// What to copy in this round
		currc = MIN(BUF_STACK_MAX, count);

		// Copy in buffer and write
		memcpy_from_user(arr, (buf + ret), currc);
		_shared_write(arr, currc, false);
		ret += currc;
		count -= currc;
	}
	mutex_release(&uartlock);

	return ret;
}

static int _set_mode(ptr_t arg)	{
	if(arg >= CHAR_MODE_LAST)	return -USER_FAULT;

	mutex_acquire(&uart.lock);
	uart.mode = (enum CHARDEV_MODE)arg;
	mutex_release(&uart.lock);
	return OK;
}

int pl011_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	switch(cmd)	{
	case CONSOLE_FCNTL_MODE:
		res = _set_mode(arg);
		break;
	default:
		res = -USER_FAULT;
		break;
	}
	return res;
}

int _receive_single(void)	{
	uint32_t r = 0;
	DMAR32(uart.base + PL011_OFF_UARTDR, r);

	char c = (char)(r & 0xff);
	if(uart.mode == CHAR_MODE_LINE_ECHO || uart.mode == CHAR_MODE_LINE)	{
		if(c == '\r')	c = '\n';

		// Backspace
		if(c == 0x7f)	{
			c = '\b';
			if(uart.curridx > 0)	{
				uart.data[--uart.curridx] = 0x00;
				if(uart.mode == CHAR_MODE_LINE_ECHO)	{
					pl011_putc(NULL, '\b'); pl011_putc(NULL, ' '); pl011_putc(NULL, '\b');
				}
			}
			return 0;
		}


		if(uart.mode == CHAR_MODE_LINE_ECHO)	{
			pl011_putc(NULL, c);
		}
	}
	if(uart.curridx < UART_DATA_BUF_SZ - 1)	{
		uart.data[uart.curridx++] = c;
	}
	return 0;
}

int pl011_receive(void)	{
	uint32_t r = 0;
	int res;
	mutex_acquire(&uartlock);

	DMAR32(uart.base + PL011_OFF_UARTRSR, r);
	ASSERT_TRUE(r == 0, "error in uart\n");

	while(poll_have_rx_data())	{
		_receive_single();
	}

	res = check_wakeup_read();

	if(res == USER_WAKEUP)	{
		int dataread = 0;
		int tid = perform_read_job(&dataread);
		thread_wakeup(tid, dataread);
	}
	mutex_release(&uartlock);
	return OK;
}

int pl011_irq_cb(int irqno)	{
	uint32_t r = 0;
	DMAR32(uart.base + PL011_OFF_UARTMIS, r);
	if(FLAG_SET(r, PL011_IMSC_RXIM))	{
		pl011_receive();
	}
	DMAW32(uart.base + PL011_OFF_UARTICR, r);
	return OK;
}

static int _pl011_irq_init(int type, int irqno, int irqflags)	{
	ASSERT_TRUE(type == 0, "Invalid type\n");
	irqno += gic_spi_offset();
	gic_set_edge(irqno);
	gic_set_priority(irqno, 1);
	gic_clear_intr(irqno);
	gic_enable_intr(irqno);
	gic_register_cb(irqno, pl011_irq_cb);
	return 0;
}


static struct fs_struct consoledev = {
	.name = "console",
	.open = vfs_empty_open,
	.close = vfs_empty_close,
	.read = pl011_read,
	.write = pl011_write,
	.getc = pl011_getc,
	.putc = pl011_putc,
	.fcntl = pl011_fcntl,
	.perm = ACL_PERM(ACL_READ|ACL_WRITE|ACL_CTRL, ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE)
};



#define TMP_INTR_TYPE  0
#define TMP_INTR_IRQNO 1
#define TMP_INTR_FLAGS 0x04

int init_pl011(void)	{
	uart.base = mmu_map_dma(UART_BASE, UART_BASE + 0x1000);
	mutex_clear(&uartlock);

	uart.data = (uint8_t*)vmmap_alloc_pages(UART_DATA_BUF_SZ / 4096, PROT_RW, 0);
	uart.maxdata = PAGE_SIZE;
	uart.curridx = uart.firstidx = 0;
	uart.mode = CHAR_MODE_BINARY;

	uart.job.thread = NULL;

	uart.write_pending = xifo_alloc(5, 2);
#if defined(CONFIG_KASAN)
	// This makes leak checking slightly easier
	kasan_never_freed(uart.write_pending);
#endif

	_init_pl011(uart.base, TMP_BAUD, TMP_CLOCKFREQ);
	_pl011_irq_init(TMP_INTR_TYPE, TMP_INTR_IRQNO, TMP_INTR_FLAGS);

	device_register(&consoledev);
	return 0;
}
early_hw_init(init_pl011);
// driver_init(init_pl011);
// int pl011_highmem_init(ptr_t linstart) {
// 	mmu_map_dma(uart.base, uart.base + 0x1000);
// 	uart.base += linstart;
// }
// highmem_init(pl011_highmem_init);
