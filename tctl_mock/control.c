/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#ifdef ANDROID
#include "device/fraunhofer/common/cml/control/control.pb-c.h"
#include "device/fraunhofer/common/cml/control/container.pb-c.h"
#else
#include "tokencontrol.pb-c.h"
#endif

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/uuid.h"

#include <getopt.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

// clang-format off
#define CONTROL_SOCKET "/tmp/testsocket"
// clang-format on
#define RUN_PATH "run"
#define DEFAULT_KEY                                                                                \
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static void
print_usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s [-s <socket file>] <command> [<command args>]\n", cmd);
	printf("\n");
	printf("commands:\n");
	printf("   list\n        Lists all containers.\n");
	printf("   list_guestos\n        Lists all installed guestos configs.\n");
	printf("   reload\n        Reloads containers from config files.\n");
	printf("   wipe_device\n        Wipes all containers on the device.\n");
	printf("   reboot\n        Reboots the whole device, shutting down any containers which are running.\n");
	printf("   create <container.conf>\n        Creates a container from the given config file.\n");
	printf("   remove <container-uuid>\n        Removes the specified container (completely).\n");
	printf("   start <container-uuid> [--key=<key>] [--setup] \n        Starts the container with the given key (default: all '0') .\n");
	printf("   stop <container-uuid>\n        Stops the specified container.\n");
	printf("   config <container-uuid>\n        Prints the config of the specified container.\n");
	printf("   update_config <container-uuid> --file=<container.conf>\n        Updates a container's config with the given config file.\n");
	printf("   state <container-uuid>\n        Prints the state of the specified container.\n");
	printf("   freeze <container-uuid>\n        Freeze the specified container.\n");
	printf("   unfreeze <container-uuid>\n        Unfreeze the specified container.\n");
	printf("   allow_audio <container-uuid>\n        Grant audio access to the specified container (cgroups).\n");
	printf("   deny_audio <container-uuid>\n        Deny audio access to the specified container (cgroups).\n");
	printf("   wipe <container-uuid>\n        Wipes the specified container.\n");
	printf("   push_guestos_config <guestos.conf> <guestos.sig> <guestos.pem>\n        (testing) Pushes the specified GuestOS config, signature, and certificate files.\n");
	printf("   remove_guestos <guestos name>\n        Remove a GuestOS by the specified name. It will only remove the OS if no container is using it anymore.\n");
	printf("   ca_register <ca.cert>\n        Registers a new certificate in trusted CA store for allowed GuestOS signatures.\n");
	printf("   pull_csr <device.csr>\n        Pulls the device csr and stores it in <device.csr>.\n");
	printf("   push_cert <device.cert>\n        Pushes back the device certificate provided by <device.cert>.\n");
	printf("   change_pin\n        Change token pin which is used for container key wrapping. Prompts for password entry.\n");
	printf("   assign_iface --iface <iface_name> <container-uuid> [--persistent]\n        Assign the specified network interface to the specified container. If the 'persistent' option is set, the container config file will be modified accordingly.\n");
	printf("   unassign_iface --iface <iface_name> <container-uuid> [--persistent]\n        Unassign the specified network interface from the specified container. If the 'persistent' option is set, the container config file will be modified accordingly.\n");
	printf("   ifaces <container-uuid>\n        Prints the list of network interfaces assigned to the specified container.\n");
	printf("   run <command> [<arg_1> ... <arg_n>] <container-uuid>\n        Runs the specified command with the given arguments inside the specified container.\n");
	printf("\n");
	exit(-1);
}

static int
sock_connect(const char *socket_file)
{
	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0)
		FATAL("Failed to create and connect to socket %s!", socket_file);
	return sock;
}

static void
send_message(int sock, ContainerToToken *msg)
{
	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)msg);
	if (msg_size < 0)
		FATAL("error sending protobuf message\n");
}

static TokenToContainer *
recv_message(int sock)
{
	TokenToContainer *resp =
		(TokenToContainer *)protobuf_recv_message(sock, &token_to_container__descriptor);
	if (!resp)
		FATAL("error receiving message\n");
	return resp;
}

static const struct option global_options[] = { { "socket", required_argument, 0, 's' },
						{ "help", no_argument, 0, 'h' },
						{ 0, 0, 0, 0 } };

static void
dump(unsigned char *mem, int len)
{
	while (len--) {
		ASSERT(len >= 0);
		fprintf(stderr, "%02x ", *mem);
		mem++;
	}

	printf("\n");
}

int
main(int argc, char *argv[])
{
	logf_register(&logf_test_write, stderr);

	bool has_response = false;
	const char *socket_file = CONTROL_SOCKET;
	int sock = 0;

	struct termios termios_before;
	tcgetattr(STDIN_FILENO, &termios_before);

	for (int c, option_index = 0;
	     - 1 != (c = getopt_long(argc, argv, "+s:h", global_options, &option_index));) {
		switch (c) {
		case 's':
			socket_file = optarg;
			break;
		default: // includes cases 'h' and '?'
			print_usage(argv[0]);
		}
	}

	if (!file_exists(socket_file))
		ERROR("Could not find socket file %s. Aborting.\n", socket_file);

	// need at least one more argument (i.e. command string)
	if (optind >= argc)
		print_usage(argv[0]);

	// build ContainerToToken message
	ContainerToToken msg = CONTAINER_TO_TOKEN__INIT;

	const char *command = argv[optind++];
	if (!strcasecmp(command, "get_atr")) {
		msg.command = CONTAINER_TO_TOKEN__COMMAND__GET_ATR;
		has_response = true;
		printf("Prepared GET_ATR command");
		goto send_message;
	}
	if (!strcasecmp(command, "unlock_token")) {
		msg.command = CONTAINER_TO_TOKEN__COMMAND__UNLOCK_TOKEN;
		has_response = true;
		printf("Prepared UNLOCK_TOKEN command");
		goto send_message;
	}
	if (!strcasecmp(command, "send_apdu")) {
		msg.command = CONTAINER_TO_TOKEN__COMMAND__SEND_APDU;
		has_response = true;
		msg.has_apdu = true;
		uint8_t *testapdu = mem_alloc0(4);
		testapdu[0] = 0xde;
		testapdu[1] = 0xca;
		testapdu[2] = 0xfb;
		testapdu[3] = 0xad;

		msg.apdu.data = testapdu;
		msg.apdu.len = 4;
		printf("Prepared SEND_APDU command");
		goto send_message;
	} else
		print_usage(argv[0]);

	// need exactly one more argument (i.e. container string)
	if (optind != argc - 1)
		print_usage(argv[0]);

	sock = sock_connect(socket_file);
	/*
	uuid = get_container_uuid_new(argv[optind], sock);
	msg.n_container_uuids = 1;
	msg.container_uuids = mem_new(char *, 1);
	msg.container_uuids[0] = mem_strdup(uuid_string(uuid));
	*/

send_message:
	if (!sock)
		sock = sock_connect(socket_file);

	protobuf_dump_message(STDERR_FILENO, (ProtobufCMessage *)&msg);
	send_message(sock, &msg);

	//handle_resp:
	// recv response if applicable
	if (has_response) {
		TRACE("[CLIENT] Awaiting response");

		TokenToContainer *resp = recv_message(sock);

		TRACE("[CLIENT] Got response. Processing");

		// do command-specific response processing
		switch (resp->return_code) {
		case TOKEN_TO_CONTAINER__CODE__OK: {
			INFO("DAEMON_TO_CONTROLLER__CODE__OK");
			printf("DAEMON_TO_CONTROLLER__CODE__OK\n");
		} break;

		case TOKEN_TO_CONTAINER__CODE__ERR_INVALID: {
			INFO("DAEMON_TO_CONTROLLER__CODE__ERR_INVALID");
			printf("DAEMON_TO_CONTROLLER__CODE__ERR_INVALID\n");
		} break;

		case TOKEN_TO_CONTAINER__CODE__ERR_CT: {
			INFO("DAEMON_TO_CONTROLLER__CODE__ERR_CT");
			printf("DAEMON_TO_CONTROLLER__CODE__ERR_CT\n");
		} break;

		case TOKEN_TO_CONTAINER__CODE__CML_TIMEOUT: {
			INFO("DAEMON_TO_CONTROLLER__CODE__CML_TIMEOUT");
			printf("DAEMON_TO_CONTROLLER__CODE__CML_TIMEOUT\n");
		} break;

		default:
			ERROR("Unknown response code");
			printf("Unkown response code");
		}

		if (resp->response.data) {
			fprintf(stderr, "The response was:\n");
			dump(resp->response.data, resp->response.len);
		} else {
			fprintf(stderr, "Data was 0, len: %lu, has_response: %d\n",
				resp->response.len, resp->has_response);
		}

		INFO("Received protobuf message was:");
		protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *)resp);
		protobuf_free_message((ProtobufCMessage *)resp);
	}

	close(sock);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_before);

	return 0;
}
