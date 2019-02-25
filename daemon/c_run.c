#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
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
int fd[MAX_NS] = { 0 };

static int
setns_cb(const char *path, const char *file, void *data)
{
	int *i = data;
	int ret = EXIT_SUCCESS;

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
	exit(EXIT_FAILURE);
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
		goto error;
	}

	for (int j = 0; j < i; j++) {
		if (setns(fd[j], 0) == -1) {	/* Join that namespace */
			FATAL_ERRNO("Could not join namespace");
			goto error;
		}
	}

	TRACE("Successfully joined all namespaces");


	mem_free(pid_string);
	mem_free(folder);
	return 0;

error:
	mem_free(pid_string);
	mem_free(folder);
	exit(EXIT_FAILURE);
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
		TRACE("[EXEC] Trying to set cgroup\n");

		elem = (char *)current->data;
		//TODO dont hardcode
		//TOD Oweak reference?
		if (strcmp(elem, "pids") != 0) {
			char *procs_path = mem_printf("/sys/fs/cgroup/%s/%s/cgroup.procs", elem, uuid_string(container_get_uuid(container)));

			TRACE("[EXEC] Trying to put into cgroup %s\n", procs_path);

			file_write_append(procs_path, pid_string, sizeof(pid_string));

			if(procs_path != NULL) {
				mem_free(procs_path);
			}
		}

		//printf("Going to next element, current: %p, next: %p\n", current, current->next);
		current = current->next;
	} while (current != first && current != NULL);

	TRACE("Done setting cgroups");

	mem_free(pid_string);
	return 0;
}

static int
do_exec (container_t *container, char *cmd, char **argv, int fd)
{
	if (-1 == dup2(fd, STDIN_FILENO)) {
		ERROR("Failed to redirect stdin to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if(-1 == dup2(fd, STDOUT_FILENO)) {
		ERROR ("Failed to redirect stdout to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if (-1 == dup2(fd, STDERR_FILENO)) {
		ERROR("Failed to redirect stderr to cmld. Exiting...");
		exit(EXIT_FAILURE);
	}

	c_run_set_cgroups(container, getpid());

	c_run_set_namespaces(getpgid(0));

	c_cap_start_child(container);


	TRACE("[EXEC: Executing command %s]", cmd);
	execve(cmd, argv, NULL);

	ERROR_ERRNO("Failed to execve");

	exit(EXIT_FAILURE);
}

static void
readloop(int from_fd, int to_fd)
{
        int count = 0;
        char buf[1024];

        while(1)
        {
            if(0 < (count = read(from_fd, &buf, sizeof(buf)-1)))
            {
                buf[count] = 0;
                write(to_fd, buf, count+1);
            } else {
				exit(EXIT_FAILURE);
			}
        }
}

int
c_run_exec_process(container_t *container, int create_pty, char *cmd, char **argv)
{
	//create new PTY
	if (create_pty) {
		TRACE("[EXEC] Starting to create new pty");
	
	    int pty_master = 0;
	
	    if(-1 == (pty_master = posix_openpt(O_RDWR)))
	    {   
	        ERROR("[EXEC] Failed to get new PTY master fd\n");
	        exit(EXIT_FAILURE);
	    }   
	
	
	    if(0 != grantpt(pty_master))
	    {   
	        printf("Failed to grantpt()\n");
	        exit(EXIT_FAILURE);
	    }   
	
	    if(0 != unlockpt(pty_master))
	    {   
	        printf("Failed to unlockpt()\n");
	        exit(EXIT_FAILURE);;
	    }   
	
	    char pty_slave_name[50];
	    ptsname_r(pty_master, pty_slave_name, sizeof(pty_slave_name));
	    TRACE("Created new pty with fd: %i, slave name: %s\n", pty_master, pty_slave_name);
	
		//fork childs for reading/writing PTY master fd
	    int pid = fork();
	
	    if(pid == -1) 
	    {   
	        ERROR("Failed to fork(), exiting...\n");
	        exit(EXIT_FAILURE);
	    }   
	    else if(pid == 0)
	    {   
	            readloop(pty_master, container_get_console_container_sock(container));
	    }   
	    else
	    { 
			// fork child to execute command
			int pid2 = fork();

			if (pid2 < 0) {
				ERROR("[EXEC] Failed to fork child to excute command.");
				exit(EXIT_FAILURE);
			} else if (pid2 == 0) {
				int pty_slave_fd = -1;

				// open PTY slave
				if (-1 == (pty_slave_fd = open(pty_slave_name, O_RDWR))) {
   				    ERROR("Failed to open pty slave: %s\n", pty_slave_name);
					//TODO check parent exits
					shutdown(pty_master, SHUT_WR);
    			    exit(EXIT_FAILURE);
				}

				const char *current_pty = ctermid(NULL);
		        DEBUG("[EXEC] Current controlling PTY is: %s\n", current_pty);
	
	    	    setsid();
	
	        	if(-1 == ioctl(STDIN_FILENO, TIOCNOTTY)) {
	    	        TRACE("[EXEC] Failed to release current controlling pty.\n");
	        	}
	
		        if(-1 == ioctl(pty_slave_fd, TIOCSCTTY, NULL)) {
		       	    ERROR("[EXEC] Failed to set controlling pty slave\n");
					exit(EXIT_FAILURE);
	    	    }
	
				// attach executed process to new PTY slave
				do_exec(container, cmd, argv, pty_slave_fd);
			} else {
				//TODO kill if executing child exits 
	        	while(1) {
	        	    readloop(container_get_console_container_sock(container), pty_master);
	        	}
			}	
	
	        exit(EXIT_SUCCESS);
	    }   
	
	    exit(EXIT_SUCCESS);
	} else {
		// attach executed process directly to console socket
		TRACE("Executing without PTY");
		do_exec(container, cmd, argv, container_get_console_container_sock(container));
	}
}
