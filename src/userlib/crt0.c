#include <fcntl.h>
#include <unistd.h>
 
extern void _exit(int);
extern int main ();
 
void _start() {
	/*
	* Open stdin, stdout and stderr
	* If any gets an unexpected result, we exit
	*/
	int in, out, err;
	in = open("/console", 0, 0);
	if(in != 0)	_exit(in);

	out = dup(in);
	if(out != 1)	_exit(out);

	err = dup(out);
	if(err != 2)	_exit(err);

    int ex = main();
    _exit(ex);
}

