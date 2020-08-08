#include "kernel.h"

/**
* Power off the computer.
*
* The architecture must register :c:type:`poweroff`, otherwise the function will
* just panic.
*/
void poweroff(void)	{
	if(osdata.cpus.poweroff == NULL)	PANIC("Poweroff has not been configured\n");

	osdata.cpus.poweroff();
}
