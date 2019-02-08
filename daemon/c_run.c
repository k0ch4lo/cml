#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/syscall.h>


#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include <macro.h>

#include "common/mem.h"
#include "common/dir.h"
#include "c_run.h"
#include "c_cgroups.h"

int setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}

#define MAX_NS 6
int fd[MAX_NS] = {0};

static int
setns_cb(const char *path, const char *file, void *data)
{
	int *i = data;

	char *ns_file = mem_printf("%s%s", path, file);
	//TRACE("Opening namespace file %s", ns_file);

	if (*i >= MAX_NS) {
		ERROR("Too many namespace files found in %s", path);
		goto error;
	}

	fd[*i] = open(ns_file, O_RDONLY);
	if (fd[*i] == -1) {
		ERROR_ERRNO("Could not open namespace file %s", ns_file);
		goto error;
	}

	*i = *i + 1;

	mem_free(ns_file);
	return 0;

error:
	mem_free(ns_file);
	abort();
}



int
c_run_set_namespaces(pid_t pid)
{
	char *pid_string = mem_printf("%d", pid);

	//TRACE("Setting namespaces for pid %s", pid_string);

	// set namespaces
	char *folder = mem_printf("/proc/%d/ns/", pid);

	int i = 0;
	if (dir_foreach(folder, &setns_cb, &i)) {
		FATAL("Could not traverse PID dir in procfs, wrong PID?");
	}

	for (int j = 0; j < i; j++) {
		if (setns(fd[j], 0) == -1) {     /* Join that namespace */
			FATAL_ERRNO("Could not join namespace");
		}
	}

	//TRACE("Successfully joined all namespaces");

	return 0;
}

int
c_run_exec_process(int console_sock_container, char *cmd, char **argv)
{
	// wait on console task socket for exec request from cmld
	//TRACE("[exec child] Trying to execute: %s, %p", cmd, (char *) argv);

	//TODO tty option
	//TODO access to container struct (no exec)!

	if (-1 == dup2(console_sock_container, STDIN_FILENO)) {
		ERROR("Failed to redirect stdin to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if(-1 == dup2(console_sock_container, STDOUT_FILENO)) {
		ERROR ("Failed to redirect stdout to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if (-1 == dup2(console_sock_container, STDERR_FILENO)) {
		ERROR("Failed to redirect stderr to cmld. Exiting...");
		exit(EXIT_FAILURE);
	}

	
	//c_run_set_namespaces(getgid());
	
	//c_cgroups_set_pid(container, getpid());


//	ConsoleToDaemon exec = CONSOLE_TO_DAEMON__INIT;
//
//	//TODO check safe
//	exec.code = CONSOLE_TO_DAEMON__CODE__EXEC_SUCCESS;
//	exec.pid = mypid;
//	
//	if (protobuf_send_message
//	    (container->console_sock_container,
//	     (ProtobufCMessage *) & exec) < 0) {
//		WARN("Could not send exec confirmation message to cmld");
//	}
//

	//TRACE("[CHILD] Executing supplied command %s, PID is: %i", cmd, getpid());
	//int r = execve(cmd, argv, NULL);
	//if(r == -1)
	//{
	//	printf("Failed to execve, errno: %s\n", strerror(errno));
	//	exit(EXIT_FAILURE);
	//}
	//execve(cmd, argv, NULL);
	//execve(cmd, argv, execve);

	int i = 0;

	char buf[100];
	buf[0] = 0;
	int count = 0;
	char * res;

	while(1)
	{
		printf("Before read\n");
		count = read(STDIN_FILENO, buf, 99);
		printf("After read\n");
		buf[count] = 0;

		write(STDOUT_FILENO, "[ECHO]", 6);
		write(STDOUT_FILENO, buf, count);
		write(STDOUT_FILENO, "\n", 1);
	}

	exit(EXIT_FAILURE);

	FILE *fd = popen ("ls -l /", "r");

	do{
	
	
		res = fgets(buf,100, fd);
		printf("%s", res);
	}
	while (res != NULL);
	
	pclose(fd);

	exit(EXIT_SUCCESS);
}
