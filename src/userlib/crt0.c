#include <fcntl.h>
 
extern void _exit(int);
extern int main ();
 
void _start() {
    int ex = main();
    _exit(ex);
}

