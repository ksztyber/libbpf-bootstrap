#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "nvmf.skel.h"

#define ARRAY_SIZE(arr) ((sizeof(arr) / sizeof((arr)[0])))

volatile bool running = true;

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int
init_socket(int family, struct sockaddr *addr, size_t addrlen)
{
	int fd, en = 1;

	fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket() failed\n");
		goto error;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &en, sizeof(en));
	if (bind(fd, addr, addrlen) != 0) {
		fprintf(stderr, "bind() failed\n");
		goto error;
	}

	if (listen(fd, 1024) < 0) {
		fprintf(stderr, "listen() failed\n");
		goto error;
	}

	return fd;
error:
	close(fd);
	return -1;
}

static void
handle_connection(struct nvmf_bpf *skel, int client_fd, int *split_fd)
{
	struct pollfd poll_fd;
	int rc, i, errsv, map_off = 0;

	/* Update the element with the input fd to attach the parse/verdict progs to that fd */
	rc = bpf_map_update_elem(bpf_map__fd(skel->maps.sock_map), &map_off, &client_fd, BPF_ANY);
	if (rc != 0) {
		errsv = errno;
		fprintf(stderr, "bpf_map_update_elem() failed: %s\n",
			strerror(errsv));
		return;
	}
	map_off++;
	for (i = 0; i < 2; ++i) {
		rc = bpf_map_update_elem(bpf_map__fd(skel->maps.sock_map), &map_off, &split_fd[i],
					 BPF_ANY);
		if (rc != 0) {
			errsv = errno;
			fprintf(stderr, "bpf_map_update_elem() failed (%d): %s\n",
				i, strerror(errsv));
			return;
		}

		map_off++;
	}

	/* Wait until the connection is closed */
	poll_fd.fd = client_fd;
	poll_fd.events = POLLRDHUP | POLLIN;
	poll(&poll_fd, 1, -1);
}

static void
signal_handler(int sig)
{
	running = false;
}

int
main(int argc, const char **argv)
{
	struct nvmf_bpf *skel;
	struct pollfd poll_fd;
	struct addrinfo hints = { 0 }, *ai;
	int i, rc = 0, client_fd[3], listen_fd = -1, num_clients = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s PORT\n", argv[0]);
		return 1;
	}

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo("127.0.0.1", argv[1], &hints, &ai);
	if (rc != 0) {
		fprintf(stderr, "Failed to parse the port: %s\n", argv[1]);
		return 1;
	}

	signal(SIGINT, signal_handler);
	libbpf_set_print(libbpf_print_fn);

	skel = nvmf_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	rc = nvmf_bpf__load(skel);
	if (rc != 0) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	rc = nvmf_bpf__attach(skel);
	if (rc != 0) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rc = bpf_prog_attach(bpf_program__fd(skel->progs.sk_parser),
			     bpf_map__fd(skel->maps.sock_map),
			     BPF_SK_SKB_STREAM_PARSER, 0);
	if (rc != 0) {
		fprintf(stderr, "bpf_prog_attach() failed: %s\n", strerror(errno));
		goto cleanup;
	}

	rc = bpf_prog_attach(bpf_program__fd(skel->progs.sk_verdict),
			     bpf_map__fd(skel->maps.sock_map),
			     BPF_SK_SKB_STREAM_VERDICT, 0);
	if (rc != 0) {
		fprintf(stderr, "bpf_prog_attach() failed: %s\n", strerror(errno));
		goto cleanup;
	}

	listen_fd = init_socket(AF_INET, ai->ai_addr, ai->ai_addrlen);
	if (listen_fd < 0) {
		goto cleanup;
	}


	poll_fd.fd = listen_fd;
	poll_fd.events = POLLIN;

	while (running) {
		rc = poll(&poll_fd, 1, 1000);
		if (rc < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "poll() failed\n");
			}

			break;
		} else if (rc == 0) {
			continue;
		}

		rc = accept(listen_fd, NULL, NULL);
		if (rc < 0) {
			fprintf(stderr, "accept() failed\n");
			goto cleanup;
		}

		client_fd[num_clients++] = rc;
		if (num_clients == ARRAY_SIZE(client_fd)) {
			handle_connection(skel, client_fd[0], &client_fd[1]);
			for (i = 0; i < ARRAY_SIZE(client_fd); ++i) {
				close(client_fd[i]);
			}

			num_clients = 0;
		}
	}
cleanup:
	if (listen_fd >= 0) {
		close(listen_fd);
	}
	nvmf_bpf__destroy(skel);
	return -rc;
}
