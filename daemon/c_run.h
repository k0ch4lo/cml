#ifndef C_RUN_H
#define C_RUN_H

#include "container.h"

int
c_run_set_namespaces(pid_t pid);

int
c_run_exec_process(int console_sock_fd, char *cmd, char **argv);

#endif //end C_RUN_H
