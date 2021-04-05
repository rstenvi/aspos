#ifndef __PICOL_H
#define __PICOL_H

enum {PICOL_OK, PICOL_ERR, PICOL_RETURN, PICOL_BREAK, PICOL_CONTINUE};
enum {PT_ESC,PT_STR,PT_CMD,PT_VAR,PT_SEP,PT_EOL,PT_EOF};

struct picolInterp {
    int level; /* Level of nesting */
    struct picolCallFrame *callframe;
    struct picolCmd *commands;
    char *result;
};

typedef int (*picolCmdFunc)(struct picolInterp *i, int argc, char **argv, void *privdata);

void picolInitInterp(struct picolInterp *i);
int picolEval(struct picolInterp *i, char *t);
int picolCommandPuts(struct picolInterp *i, int argc, char **argv, void *pd);
void picolRegisterCoreCommands(struct picolInterp *i);
int picolRegisterCommand(struct picolInterp *i, char *name, picolCmdFunc f, void *privdata);

// Custom commands
int picol_cat(struct picolInterp *i, int argc, char **argv, void *pd);
int picol_poweroff(struct picolInterp *i, int argc, char **argv, void *pd);

// Loop
int picol_loop(const char* pre, struct picolInterp* interp, int fdin, int fdout);
#endif
