#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <getopt.h>

#include "parser/parser.h"
#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "hcireplay.h"
#include "hciseq.h"
#include "monitor/bt.h"
#include "config.h"

struct hciseq dumpseq;
int fd;
int pos;
struct timeval start;

int epoll_fd;
struct epoll_event epoll_event;
#define MAX_EPOLL_EVENTS 1

static __useconds_t timeval_diff(struct timeval *l, struct timeval *r, struct timeval *diff) {
	int tmpsec;

	/* make sure we keep usec difference positive */
	if(r->tv_usec > l->tv_usec) {
		tmpsec = (r->tv_usec - l->tv_usec) / 1000000 + 1;
		r->tv_sec += tmpsec;
		r->tv_usec -= 1000000 * tmpsec;
	}

	if((l->tv_usec - r->tv_usec) > 1000000) {
		tmpsec = (r->tv_usec - l->tv_usec) / 1000000;
		r->tv_sec -= tmpsec;
		r->tv_usec += 1000000 * tmpsec;
	}

	diff->tv_sec = l->tv_sec - r->tv_sec ;
	diff->tv_usec = l->tv_usec - r->tv_usec;

	return (diff->tv_sec * 1000000) + diff->tv_usec;
}

static inline __useconds_t get_rel_ts(struct timeval *start, struct timeval *diff) {
	struct timeval now;
	gettimeofday(&now, NULL);
	return timeval_diff(&now, start, diff);
}

static void calc_rel_ts() {
	struct timeval start;
	struct framenode *tmp;

	start = dumpseq.current->frame->ts;
	tmp = dumpseq.current;
	while(tmp != NULL) {
		timeval_diff(&tmp->frame->ts, &start, &tmp->ts_rel);
		tmp = tmp->next;
	}
}

static inline int read_n(int fd, char *buf, int len)
{
	int t = 0, w;

	while (len > 0) {
		if ((w = read(fd, buf, len)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w; buf += w; t += w;
	}
	return t;
}

static int parse_hcidump(int fd, struct frame *frm) {
	struct hcidump_hdr dh;
	int n;

	n = read_n(fd, (void *) &dh, HCIDUMP_HDR_SIZE);
	if (n < 0)
		return -1;
	if (!n)
		return 0;

	frm->data_len = btohs(dh.len);
	n = read_n(fd, frm->data, frm->data_len);

	frm->in = dh.in;
	frm->ts.tv_sec  = btohl(dh.ts_sec);
	frm->ts.tv_usec = btohl(dh.ts_usec);

	return n;
}

static int parse_pktlog(int fd, struct frame *frm) {
	struct pktlog_hdr ph;
	int n;

	n = read_n(fd, (void *) &ph, PKTLOG_HDR_SIZE);
	if (n < 0)
		return -1;
	if (!n)
		return 0;

	switch (ph.type) {
	case 0x00:
		((uint8_t *) frm->data)[0] = HCI_COMMAND_PKT;
		frm->in = 0;
		break;
	case 0x01:
		((uint8_t *) frm->data)[0] = HCI_EVENT_PKT;
		frm->in = 1;
		break;
	case 0x02:
		((uint8_t *) frm->data)[0] = HCI_ACLDATA_PKT;
		frm->in = 0;
		break;
	case 0x03:
		((uint8_t *) frm->data)[0] = HCI_ACLDATA_PKT;
		frm->in = 1;
		break;
	default:
		lseek(fd, ntohl(ph.len) - 9, SEEK_CUR);
		return 1; //TODO: fix continue
	}

	frm->data_len = ntohl(ph.len) - 8;
	n = read_n(fd, frm->data + 1, frm->data_len - 1);

	uint64_t ts;
	ts = ntoh64(ph.ts);
	frm->ts.tv_sec = ts >> 32;
	frm->ts.tv_usec = ts & 0xffffffff;

	return n;
}

static int parse_btsnoop(int fd, struct frame *frm, struct btsnoop_hdr *hdr) {
	struct btsnoop_pkt pkt;
	uint8_t pkt_type;
	int n;

	n = read_n(fd, (void *) &pkt, BTSNOOP_PKT_SIZE);
	if (n < 0)
		return -1;
	if (!n)
		return 0;

	switch (ntohl(hdr->type)) {
	case 1001:
		if (ntohl(pkt.flags) & 0x02) {
			if (ntohl(pkt.flags) & 0x01)
				pkt_type = HCI_EVENT_PKT;
			else
				pkt_type = HCI_COMMAND_PKT;
		} else
			pkt_type = HCI_ACLDATA_PKT;

		((uint8_t *) frm->data)[0] = pkt_type;

		frm->data_len = ntohl(pkt.len) + 1;
		n = read_n(fd, frm->data + 1, frm->data_len - 1);
		break;

	case 1002:
		frm->data_len = ntohl(pkt.len);
		n = read_n(fd, frm->data, frm->data_len);
		break;
	}

	uint64_t ts;
	frm->in = ntohl(pkt.flags) & 0x01;
	ts = ntoh64(pkt.ts) - 0x00E03AB44A676000ll;
	frm->ts.tv_sec = (ts / 1000000ll) + 946684800ll;
	frm->ts.tv_usec = ts % 1000000ll;

	/*
	 * determine direction of packet for testing
	 * can probably be removed later
	 */
	if (((uint8_t *) frm->data)[0] == HCI_COMMAND_PKT) {
		frm->in = 0;
	} else if (((uint8_t *) frm->data)[0] == HCI_EVENT_PKT) {
		frm->in = 1;
	}

	return n;
}

static int parse_dump(int fd, struct hciseq *seq, unsigned long flags)
{
	struct frame *frm;
	struct btsnoop_hdr bh;
	int n;

	int count;
	struct framenode *nodeptr;
	struct framenode *last;
	last = NULL;

	if (flags & DUMP_BTSNOOP) {
		//read BTSnoop header once
		if (read_n(fd, (void *) &bh, BTSNOOP_HDR_SIZE) != BTSNOOP_HDR_SIZE) {
			 return -1;
		}
	}

	count = 0;
	while (1) {
		frm = malloc(sizeof(struct frame));
		frm->data = malloc(HCI_MAX_FRAME_SIZE);

		if (flags & DUMP_PKTLOG)
			n = parse_pktlog(fd, frm);
		else if (flags & DUMP_BTSNOOP)
			n = parse_btsnoop(fd, frm, &bh);
		else
			n = parse_hcidump(fd, frm);

		if(n <= 0)
			return n;

		frm->ptr = frm->data;
		frm->len = frm->data_len;

		nodeptr = malloc(sizeof(struct framenode));
		nodeptr->frame = frm;

		if(last == NULL) {
			seq->frames = nodeptr;
			nodeptr->next = NULL;
			last = nodeptr;
		} else {
			last->next = nodeptr;
			last = nodeptr;
		}
		seq->len = ++count;
	}

	return 0;
}

static int send_frm(struct frame *frm) {
	int n;

	n = write(fd, frm->data, frm->data_len);

	return n;
}

static int recv_frm(int fd, struct frame *frm) {
	int i,n;
	int nevs;
	uint8_t buf[HCI_MAX_FRAME_SIZE];
	struct epoll_event ev[MAX_EPOLL_EVENTS];

	nevs = epoll_wait(epoll_fd, ev, MAX_EPOLL_EVENTS, -1);
	if(nevs < 0) {
		perror("Failed to receive");
	}

	for (i = 0; i < nevs; i++) {
		if (ev[i].events & (EPOLLERR | EPOLLHUP)) {
			perror("Failed to receive");
			return -1;
		}

		if((n = read(fd, (void*)&buf, HCI_MAX_FRAME_SIZE)) > 0) {
			memcpy(frm->data, buf, n);
			fflush(stdout);
		}
	}

	return n;
}

static void replay_cmd(const void *data, uint16_t len) {
	struct frame frm_in;
	struct frame *frm_cur = dumpseq.current->frame;
	struct frame *frm_next = dumpseq.current->next->frame;
	const struct bt_hci_cmd_hdr *hdr_in = data+1;
	const struct bt_hci_cmd_hdr *hdr_cur = frm_cur->data+1;
	uint16_t opcode_in;
	uint16_t opcode_cur;
	struct framenode *frm_ptr;
	int pos;

	opcode_in = le16_to_cpu(hdr_in->opcode);
	opcode_cur = le16_to_cpu(hdr_cur->opcode);

	if(opcode_in == opcode_cur) {
		//TODO: check rest of frame
		printf("< [%d/%d]\n", pos, dumpseq.len);
	} else {
		printf("< [W] unexpected opcode - waiting for (0x%2.2x|0x%4.4x), was (0x%2.2x|0x%4.4x) \n", cmd_opcode_ogf(opcode_cur), cmd_opcode_ocf(opcode_cur), cmd_opcode_ogf(opcode_in), cmd_opcode_ocf(opcode_in));

		if((pos = find_by_opcode(dumpseq.current, &frm_ptr, opcode_in)) > 0) {
			printf("    found matching packet at position %d", pos);
		}
	}
}

static void process_in();
static void process_out();

static void process_next() {
	dumpseq.current = dumpseq.current->next;
	pos++;

	if(dumpseq.current == NULL) {
		printf("Done");
		return;
	}

	if(dumpseq.current->frame->in == 1) {
		process_out();
	} else {
		process_in();
	}
}

static void process_in() {
	static struct frame frm;
	static uint8_t data[HCI_MAX_FRAME_SIZE];
	uint8_t pkt_type;

	frm.data = &data;
	frm.ptr = frm.data;

	if(recv_frm(fd, &frm) < 0) {
		printf("Could not receive\n");
		return;
	}

	pkt_type = ((const uint8_t *) data)[0];

	switch (pkt_type) {
	case BT_H4_CMD_PKT:
		replay_cmd(data, frm.len);
		break;
	case BT_H4_ACL_PKT:
		//replay_acl(data, frm.len);
		break;
	default:
		printf("Unsupported packet 0x%2.2x\n", pkt_type);
		break;
	}


	process_next();
}

static void process_out() {
	//TODO: delay?
	printf("> [%d/%d]\n", pos, dumpseq.len);
	send_frm(dumpseq.current->frame);
	process_next();
}

static int vhci_open() {
	fd = open("/dev/vhci", O_RDWR | O_NONBLOCK);
	if((epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
		return -1;
	}

	epoll_event.events = EPOLLIN;
	epoll_event.data.fd = fd;

	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, epoll_event.data.fd, &epoll_event) < 0) {
		return -1;
	}

	return fd;
}

static int vhci_close() {
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, epoll_event.data.fd, NULL);
	return close(fd);
}

static int client_connect() {
	const char *path = "/tmp/hcireplay-server";
	struct sockaddr_un addr;
	int fd;
	uint8_t buf[4096];

	//init address
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	//init socket fd
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Failed to open server socket\n");
		return -1;
	}

	return connect(fd, (struct sockaddr *) &addr, sizeof(addr));
}

static int client_disconnect() {
	return close(fd);
}

static void delete_list() {
	struct framenode *node, *tmp;

	node = dumpseq.frames;
	while(node != NULL) {
		tmp = node;
		node = node->next;

		free(tmp->frame->data);
		free(tmp->frame);
		free(tmp);
	}
}

static void usage(void)
{
	printf("hcireplay - Bluetooth replayer\n"
		"Usage:\thcireplay-client [options] file\n"
		"options:\n"
		"\t-v, --version         Give version information\n"
		"\t-h, --help            Give a short usage message\n");
}

static const struct option main_options[] = {
	{ "version",	no_argument,	   NULL, 'v'	},
	{ "help",	no_argument,	   NULL, 'h'	},
	{ }
};

int main(int argc, char *argv[])
{
	unsigned long flags = 0;
	unsigned long filter = ~0L;
	int device = 0;
	int defpsm = 0;
	int defcompid = DEFAULT_COMPID;
	int opt, pppdump_fd = -1, audio_fd = -1;
	uint16_t obex_port;

	int dumpfd;
	int i;

	while(1) {
		int opt;

		opt = getopt_long(argc, argv, "vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		usage();
		return EXIT_FAILURE;
	}

	if((fd = vhci_open()) < 0) {
		perror("Failed to open VHCI interface");
		return 1;
	}

	dumpfd = open(argv[optind], O_RDONLY);
	if(dumpfd < 0) {
		perror("Failed to open dump file");
	}

	flags |= DUMP_BTSNOOP;
	flags |= DUMP_VERBOSE;
	init_parser(flags, filter, defpsm, defcompid, pppdump_fd, audio_fd);
	if(parse_dump(dumpfd, &dumpseq, flags) < 0) {
		fprintf(stderr, "Error parsing dump file\n");
		vhci_close();
		return 1;
	}
	dumpseq.current = dumpseq.frames;

	printf("Running.\n");
	process_next();

	delete_list();
	vhci_close();
	printf("Terminating\n");

	return 0;
}
