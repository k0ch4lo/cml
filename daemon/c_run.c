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
#include "common/file.h"
#include "hardware.h"
#include "container.h"
#include "c_run.h"
#include "c_cgroups.h"
#include "c_cap.h"

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
	TRACE("Opening namespace file %s", ns_file);

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

	TRACE("Setting namespaces for pid %s", pid_string);

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

	TRACE("Successfully joined all namespaces");

	return 0;
}

int
c_run_set_cgroups(const container_t *container, const pid_t pid)
{
	char *pid_string = mem_printf("%d", pid);

	// set cgroups
	list_t *first = hardware_get_active_cgroups_subsystems();
	list_t *current = first;
	char *elem = NULL;

	do {
		TRACE("Trying to set cgroup\n");

		elem = (char *) current->data;
		//TODO dont hardcode
		//TOD Oweak reference?
		if(strcmp(elem,"pids") != 0)
		{
			char *procs_path = mem_printf("/sys/fs/cgroup/%s/%s/cgroup.procs", elem, uuid_string(container_get_uuid(container)));

			TRACE("Trying to put into cgroup %s\n", procs_path);

			file_write_append(procs_path, pid_string, sizeof(pid_string));
		}

		//printf("Going to next element, current: %p, next: %p\n", current, current->next);
		current = current->next;
	} while(current != first && current != NULL);

	TRACE("Done setting cgroups");

	return 0;	
}

int
c_run_exec_process(container_t *container, char *cmd, char **argv)
{
	if (-1 == dup2(container_get_console_container_sock(container), STDIN_FILENO)) {
		ERROR("Failed to redirect stdin to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if(-1 == dup2(container_get_console_container_sock(container), STDOUT_FILENO)) {
		ERROR ("Failed to redirect stdout to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if (-1 == dup2(container_get_console_container_sock(container), STDERR_FILENO)) {
		ERROR("Failed to redirect stderr to cmld. Exiting...");
		exit(EXIT_FAILURE);
	}


	c_run_set_cgroups(container, getpid());
	
	c_run_set_namespaces(getgid());
	
	c_cap_start_child(container);

	printf("Trying to exec");
	execve(cmd, argv, NULL);

	ERROR_ERRNO("Failed to execve");

	exit(EXIT_FAILURE);
}
