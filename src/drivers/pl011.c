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


#define UARTIFLS_TXIFLSEL_EIGHT 0b000
#define UARTIFLS_RXIFLSEL_EIGHT (0b000 << 3)

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

enum CHARDEV_MODE {
	CHAR_MODE_BYTE = 0,
	CHAR_MODE_LINE,
};

struct uart_read {
	void* uaddr;
	size_t max;
	int tid;
};

struct uart_struct {
	ptr_t base;

	// Buffer we maintain
	uint8_t* data;
	size_t maxdata;
	size_t firstidx, curridx;

	enum CHARDEV_MODE mode;

	struct uart_read job;
};

struct uart_struct uart;

#define UART_BASE 0x09000000


#define TMP_CLOCKFREQ 0x16e3600
#define TMP_BAUD      115200

volatile uint8_t uartlock;

#if defined(CONFIG_EARLY_UART)
static int _init_pl011(ptr_t base, uint32_t baud, uint32_t clk);
static bool poll_have_rx_data()	{
	uint32_t r = 0;
	DMAR32(uart.base + 0x18, r);
	return !(r & UART_FR_RXFE);
}

int uart_early_putc(char c)	{
	mutex_acquire(&uartlock);
	DMAW32(uart.base, (uint32_t)c);
	mutex_release(&uartlock);
	return OK;
}

int uart_early_getc(void)	{
	uint32_t r = 0;
	while(!poll_have_rx_data()) ;
	DMAR32(uart.base, r);
	return (r & 0xff);
}

int uart_early_init()	{
	uart.base = UART_BASE;
	mutex_clear(&uartlock);
//	int r = _init_pl011(uart.base, TMP_BAUD, TMP_CLOCKFREQ);
	return 0;
}

int uart_early_write(const char* str)	{
	while(*str != 0x00)	uart_early_putc(*str++);
}
#endif

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

	/*
	uint32_t div = (clk * 4) / baud;

	// Integer baud register
	DMAW32(base + PL011_OFF_UARTIBRD, (div >> 6));

	// Fractional baud register
	DMAW32(base + PL011_OFF_UARTFBRD, (div & 0x3f));
*/

	// Clear all interrupts
	DMAW32(base + PL011_OFF_UARTICR, ((1<<11)-1));

//	DMAW32(base + PL011_OFF_UARTDMACR, 1|2|4);

	// Write to PL011_OFF_UARTLCR_H MUST come after IBRD and FBRD
	// TX = 8 bits, 1 stop bit, no parity, fifo
	DMAW32(base + PL011_OFF_UARTLCR_H, PL011_LCRH_WLEN_8/* | PL011_LCRH_FEN*/);

	// Enable interrupts for receive, transmit and receive timeout
	DMAW32(base + PL011_OFF_UARTIMSC, /*((1<<11)-1)*/(PL011_IMSC_RXIM /*| PL011_IMSC_TXIM*/ | PL011_IMSC_RTIM));


	// Interrupt when FIFO is 1/8 full
//	DMAW32(base + PL011_OFF_UARTIFLS, (UARTIFLS_TXIFLSEL_EIGHT | UARTIFLS_RXIFLSEL_EIGHT));

	// Enable UART
	DMAW32(base + PL011_OFF_UARTCR,
		(PL011_CR_UARTEN | PL011_CR_SIREN | PL011_CR_TXE | PL011_CR_RXE));


	pl011_flush(base);
	return 0;
}

static int _check_read_job()	{

}
//int pl011_open(struct vfsopen* o, void* buf, int count)	{


static int check_wakeup_read(void)	{
	// Check if we have any data to send
	if(uart.curridx <= 0 || uart.firstidx == uart.curridx)	return OK;

	// Check if anyone wants data
	if(uart.job.tid < 0)	return OK;

	char last = uart.data[uart.curridx-1];
	int ret = OK;

	
	if(uart.mode == CHAR_MODE_LINE && last == '\n')	{
		ret = USER_WAKEUP;
	}
	else if( (uart.curridx - uart.firstidx) == uart.job.max)	{
		ret = USER_WAKEUP;
	}
	else if(uart.mode == CHAR_MODE_BYTE)	{
		ret = USER_WAKEUP;
	}
	
	// If we get here, we should not return to user-mode
	return ret;
}

static int perform_read_job(int* res)	{
	int tid = uart.job.tid;
	int dataread = (uart.curridx - uart.firstidx);
	*res = dataread;
	copy_to_user(uart.job.uaddr, &(uart.data[uart.firstidx]), dataread);
	uart.job.tid = -1;
	return tid;
}

int pl011_read(struct vfsopen* o, void* buf, size_t count)	{
	uart.job.tid = current_tid();
	uart.job.uaddr = buf;
	uart.job.max = count;

	int res = check_wakeup_read();
	if(res == USER_WAKEUP)	{
		int uret = 0, tid;
		tid = perform_read_job(&uret);
		return OK;
	}
	return -BLOCK_THREAD;
}

int pl011_write(struct vfsopen* o, void* buf, size_t count)	{
	size_t i;
	char* arr = (char*)buf;
	mutex_acquire(&uartlock);
	for(i = 0; i < count; i++)	{
		DMAW32(uart.base, (uint32_t)(arr[i]));
	}
	mutex_release(&uartlock);
	return count;
}

int pl011_receive(void)	{
	uint32_t r = 0;
	int res;
	mutex_acquire(&uartlock);
	DMAR32(uart.base, r);

	char c = (char)(r & 0xff);
	if(c == '\r')	c = '\n';
	uart.data[uart.curridx++] = c;

	res = check_wakeup_read();


	if(res == USER_WAKEUP)	{
		int dataread = 0;
		int tid = perform_read_job(&dataread);
		mutex_release(&uartlock);
		thread_wakeup(tid, dataread);
	}
	mutex_release(&uartlock);
	return OK;
}

int pl011_irq_cb(void)	{
	uint32_t r = 0;
	DMAR32(uart.base + PL011_OFF_UARTMIS, r);
	if(FLAG_SET(r, PL011_IMSC_RXIM))	{
		pl011_receive();
	}
	DMAW32(uart.base + PL011_OFF_UARTICR, r);
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
	.read = pl011_read,
	.write = pl011_write,
};



#define TMP_INTR_TYPE  0
#define TMP_INTR_IRQNO 1
#define TMP_INTR_FLAGS 0x04

int init_pl011(void)	{
	logi("pl011 not ready yet\n");

	uart.data = (uint8_t*)vmmap_alloc_page(PROT_RW, 0);
	uart.maxdata = PAGE_SIZE;
	uart.curridx = uart.firstidx = 0;
	uart.mode = CHAR_MODE_LINE;

	uart.job.tid = -1;

	_init_pl011(uart.base, TMP_BAUD, TMP_CLOCKFREQ);
	_pl011_irq_init(TMP_INTR_TYPE, TMP_INTR_IRQNO, TMP_INTR_FLAGS);

	device_register(&consoledev);
	return 0;
}

driver_init(init_pl011);

int pl011_highmem_init(ptr_t linstart) {
	mmu_map_dma(uart.base, uart.base + 0x1000);
	uart.base += linstart;
}

highmem_init(pl011_highmem_init);
