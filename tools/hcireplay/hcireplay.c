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
#include <stdbool.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "hcireplay.h"
#include "hciseq.h"
#include "monitor/bt.h"
#include "config.h"
#include "monitor/btsnoop.h"
#include "monitor/control.h"
#include "monitor/packet.h"
#include "emulator/btdev.h"
#include "../../config.h"

#define MAXMSG 128

#define TIMING_NONE 0
#define TIMING_DELTA 1

struct hciseq dumpseq;
struct hciseq_type_cfg type_cfg;

int fd;
int pos = 1;
struct timeval start;

int epoll_fd;
struct epoll_event epoll_event;
#define MAX_EPOLL_EVENTS 1

int timeout = -1;
int skipped = 0;
int timing = TIMING_NONE;
double factor = 1;
bool verbose = false;

struct btdev *btdev;

__useconds_t timeval_diff(struct timeval *l, struct timeval *r, struct timeval *diff) {
	int tmpsec;
	static struct timeval tmp;

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

	/* use local variable if we only need return value */
	if(diff == NULL)
		diff = &tmp;

	diff->tv_sec = l->tv_sec - r->tv_sec ;
	diff->tv_usec = l->tv_usec - r->tv_usec;

	return (diff->tv_sec * 1000000) + diff->tv_usec;
}

int timeval_cmp(struct timeval *l, struct timeval *r) {
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

	if(l->tv_sec > r->tv_sec) {
		return 1;
	} else if(l->tv_sec < r->tv_sec) {
		return -1;
	} else {
		if(l->tv_usec > r->tv_usec) {
			return 1;
		} else if(l->tv_usec > r->tv_usec) {
			return -1;
		} else {
			return 0;
		}
	}
}

static inline __useconds_t get_rel_ts(struct timeval *start, struct timeval *diff) {
	struct timeval now;
	gettimeofday(&now, NULL);
	return timeval_diff(&now, start, diff);
}

static inline timeval_get_usec(struct timeval *ts) {
	return (ts->tv_sec * 1000000) + ts->tv_usec;
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
	return n;
}

static int parse_dump(int fd, struct hciseq *seq, unsigned long flags)
{
	struct frame *frm;
	struct btsnoop_hdr bh;
	int n;

	int count;
	struct hciseq_node *nodeptr;
	struct hciseq_node *last;
	last = seq->current;

	if (flags & DUMP_BTSNOOP) {
		//read BTSnoop header once
		if (read_n(fd, (void *) &bh, BTSNOOP_HDR_SIZE) != BTSNOOP_HDR_SIZE) {
			 return -1;
		}
	}

	count = seq->len;
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

		nodeptr = malloc(sizeof(struct hciseq_node));
		nodeptr->frame = frm;
		nodeptr->attr = (struct hciseq_attr*) malloc(sizeof(struct hciseq_attr));
		nodeptr->attr->action = HCISEQ_ACTION_REPLAY;

		if(last == NULL) {
			seq->frames = nodeptr;
			last = nodeptr;
		} else {
			last->next = nodeptr;
			last = nodeptr;
		}
		nodeptr->next = NULL;
		seq->len = ++count;
	}

	return 0;
}

static void dump_frame(struct frame *frm) {
	uint8_t pkt_type = ((const uint8_t *) frm->data)[0];
	switch (pkt_type) {
	case BT_H4_CMD_PKT:
		packet_hci_command(&start, 0x00, frm->data + 1, frm->data_len - 1);
		break;
	case BT_H4_EVT_PKT:
		packet_hci_event(&start, 0x00, frm->data + 1, frm->data_len - 1);
		break;
	case BT_H4_ACL_PKT:
		if(frm->in)
			packet_hci_acldata(&start, 0x00, 0x01, frm->data + 1, frm->data_len - 1);
		else
			packet_hci_acldata(&start, 0x00, 0x00, frm->data + 1, frm->data_len - 1);
		break;
	default:
		//TODO: hex dump
		break;
	}
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

	nevs = epoll_wait(epoll_fd, ev, MAX_EPOLL_EVENTS, timeout);
	if(nevs < 0) {
		perror("Failed to receive");
	} else if(nevs == 0) {
		return 0;
	}

	for (i = 0; i < nevs; i++) {
		if (ev[i].events & (EPOLLERR | EPOLLHUP)) {
			perror("Failed to receive");
			return -1;
		}

		if((n = read(fd, (void*)&buf, HCI_MAX_FRAME_SIZE)) > 0) {
			memcpy(frm->data, buf, n);
			frm->data_len = n;
		}
	}

	return n;
}

void btdev_send (const void *data, uint16_t len, void *user_data) {
	struct frame frm;
	frm.data = data;
	frm.len = len;
	frm.data_len = len;
	frm.in = 1;
	printf("[Emulator ] ");
	dump_frame(&frm);
	send_frm(&frm);
}

void btdev_recv(struct frame *frm) {
	frm->in = 0;
	printf("[Emulator ] ");
	dump_frame(frm);
	btdev_receive_h4(btdev, frm->data, frm->data_len);
}

static struct hciseq_attr* get_type_attr(struct frame *frm) {
	uint8_t pkt_type = ((const uint8_t *) frm->data)[0];
	uint16_t opcode;
	uint8_t evt;

	switch (pkt_type) {
	case BT_H4_CMD_PKT:
		opcode = *((uint16_t*) (frm->data+1));
		if(opcode > 0x2FFF)
			return NULL;
		return type_cfg.cmd[opcode];
	case BT_H4_EVT_PKT:
		evt = *((uint8_t*)(frm->data+1));

		/* use attributes of opcode for 'Command Complete' events */
		if(evt == 0x0e) {
			opcode = *((uint16_t*) (frm->data+4));
			return type_cfg.cmd[opcode];
		}

		return type_cfg.evt[evt];
	case BT_H4_ACL_PKT:
		return type_cfg.acl;
	default:
		return NULL;
	}
}


static bool check_match(struct frame *l, struct frame *r, char *msg) {
	uint8_t type_l = ((const uint8_t *) l->data)[0];
	uint8_t type_r = ((const uint8_t *) l->data)[0];
	uint16_t opcode_l, opcode_r;
	uint8_t evt_l, evt_r;

	if(type_l != type_r) {
		snprintf(msg, MAXMSG, "! Wrong packet type - expected (0x%2.2x), was (0x%2.2x)", type_l, type_r);
		return false;
	}

	switch (type_l) {
	case BT_H4_CMD_PKT:
		opcode_l = *((uint16_t*) (l->data+1));
		opcode_r = *((uint16_t*) (r->data+1));
		if(opcode_l != opcode_r) {
			snprintf(msg, MAXMSG, "! Wrong opcode - expected (0x%2.2x|0x%4.4x), was (0x%2.2x|0x%4.4x)", cmd_opcode_ogf(opcode_l), cmd_opcode_ocf(opcode_l), cmd_opcode_ogf(opcode_r), cmd_opcode_ocf(opcode_r));
			return false;
		} else {
			return true;
		}
	case BT_H4_EVT_PKT:
		evt_l = *((uint8_t*)(l->data+1));
		evt_r = *((uint8_t*)(r->data+1));
		if(evt_l != evt_r) {
			snprintf(msg, MAXMSG, "! Wrong event type - expected (0x%2.2x), was (0x%2.2x)", evt_l, evt_r);
			return false;
		} else {
			return true;
		}
	case BT_H4_ACL_PKT:
		if(l->data_len != r->data_len)
			return false;

		if(!memcmp(l->data, r->data, l->data_len))
			return true;
		else
			return false;
	default:
		snprintf(msg, MAXMSG, "! Unknown packet type (0x%2.2x)", type_l);

		if(l->data_len != r->data_len)
			return false;

		if(!memcmp(l->data, r->data, l->data_len))
			return true;
		else
			return false;
	}
}

static int process_in() {
	static struct frame frm;
	static uint8_t data[HCI_MAX_FRAME_SIZE];
	uint8_t pkt_type;
	int n;
	struct hciseq_attr *attr;
	bool match;
	char msg[MAXMSG];

	frm.data = &data;
	frm.ptr = frm.data;

	n = recv_frm(fd, &frm);
	if(n < 0) {
		printf("Could not receive\n");
		return 0;
	} else if(n == 0){
		printf("[%4d/%4d] Timeout\n", pos, dumpseq.len);
		skipped++;
		return 1;
	}

	/* is this the packet in the sequence? */
	msg[0] = '\0';
	match = check_match(dumpseq.current->frame, &frm, msg);

	/* check type config */
	attr = get_type_attr(&frm);
	if(attr != NULL) {
		if(attr->action == HCISEQ_ACTION_SKIP) {
			if(match) {
				printf("[%4d/%4d] SKIPPING\n", pos, dumpseq.len);
				return 1;
			} else {
				printf("[ Unknown ] %s\n            ", msg);
				dump_frame(&frm);
				printf("            SKIPPING\n");
				return 0;
			}
		}
		if(attr->action == HCISEQ_ACTION_EMULATE) {
			if(match) {
				printf("[%4d/%4d] EMULATING\n", pos, dumpseq.len);
			} else {
				printf("[ Unknown ] %s\n            ", msg);
				printf("EMULATING\n");
			}

			btdev_recv(&frm);

			if(match)
				return 1;
			else
				return 0;
		}
	}

	/* process packet if match */
	if(match) {
		printf("[%4d/%4d] ", pos, dumpseq.len);

		if(dumpseq.current->attr->action == HCISEQ_ACTION_EMULATE) {
			btdev_recv(&frm);
			return 1;
		}

		dump_frame(&frm);
		return 1;
	} else {
		printf("[ Unknown ] %s\n            ", msg);
		dump_frame(&frm);
		return 0;
	}
}

static int process_out() {
	uint8_t pkt_type;
	struct hciseq_attr *attr;

	/* emulator sends response automatically */
	if(dumpseq.current->attr->action == HCISEQ_ACTION_EMULATE) {
		return 1;
	}

	/* use type config if set */
	attr = get_type_attr(dumpseq.current->frame);
	if(attr != NULL) {
		if(attr->action == HCISEQ_ACTION_SKIP) {
			return 1;
		}
		if(attr->action == HCISEQ_ACTION_EMULATE) {
			return 1;
		}
	}

	pkt_type = ((const uint8_t *) dumpseq.current->frame->data)[0];

	switch (pkt_type) {
	case BT_H4_EVT_PKT:
		printf("[%4d/%4d] ", pos, dumpseq.len);
		dump_frame(dumpseq.current->frame);
		send_frm(dumpseq.current->frame);
		break;
	case BT_H4_ACL_PKT:
		printf("[%4d/%4d] ", pos, dumpseq.len);
		dump_frame(dumpseq.current->frame);
		send_frm(dumpseq.current->frame);
		break;
	default:
		printf("Unsupported packet 0x%2.2x\n", pkt_type);
		break;
	}
	return 1;
}

static void process() {
	__useconds_t delay;
	struct timeval last;
	int processed;

	gettimeofday(&last, NULL);
	do {
		if(dumpseq.current->attr->action == HCISEQ_ACTION_SKIP) {
			printf("[%4d/%4d] SKIPPING\n            ", pos, dumpseq.len);
			dump_frame(dumpseq.current->frame);
			dumpseq.current = dumpseq.current->next;
			pos++;
			continue;
		}

		/* delay */
		if(timing == TIMING_DELTA) {
			/* consider exec time of process_out()/process_in() */
			get_rel_ts(&last, &last);
			if(timeval_cmp(&dumpseq.current->attr->ts_diff, &last) >= 0) {
				delay = timeval_diff(&dumpseq.current->attr->ts_diff, &last, NULL);
				delay *= factor;
				if(usleep(delay) == -1) {
					printf("Delay failed\n");
				}
			} else {
				/* exec time was longer than delay */
				printf("Packet delay\n");
			}
			gettimeofday(&last, NULL);
		}

		if(dumpseq.current->frame->in == 1) {
			processed = process_out();
		} else {
			processed = process_in();
		}

		if(processed) {
			dumpseq.current = dumpseq.current->next;
			pos++;
		}
	} while(dumpseq.current != NULL);

	printf("Done\n");
	printf("Processed %d out of %d\n", dumpseq.len-skipped, dumpseq.len);
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

static void delete_list() {
	struct hciseq_node *node, *tmp;

	node = dumpseq.frames;
	while(node != NULL) {
		tmp = node;
		node = node->next;

		free(tmp->frame->data);
		free(tmp->frame);
		free(tmp->attr);
		free(tmp);
	}
}

static void delete_type_cfg() {
	int i;

	for(i = 0; i < 12288; i++) {
		if(type_cfg.cmd[i] != NULL)
			free(type_cfg.cmd[i]);
	}
	for(i = 0; i < 256; i++) {
		if(type_cfg.evt[i])
			free(type_cfg.evt[i]);
	}
	if(type_cfg.acl != NULL)
		free(type_cfg.acl);
}

static void usage(void)
{
	printf("hcireplay - Bluetooth replayer\n"
		"Usage:\thcireplay-client [options] file...\n"
		"options:\n"
		"\t-d, --timing={none|delta}    Specify timing mode\n"
		"\t-m, --factor=<value>         Use timing modifier\n"
		"\t-t, --timeout=<value>        Use timeout when receiving\n"
		"\t-c, --config=<file>          Use config file\n"
		"\t-v, --verbose                Enable verbose output\n"
		"\t    --version                Give version information\n"
		"\t    --help                   Give a short usage message\n");
}

static const struct option main_options[] = {
	{ "timing",	required_argument,		NULL, 'd'	},
	{ "factor",	required_argument,		NULL, 'm'	},
	{ "timeout",	required_argument,	NULL, 't'	},
	{ "config",	required_argument,	    NULL, 'c'	},
	{ "verbose",    no_argument,        NULL, 'v'	},
	{ "version",    no_argument,        NULL, 'V'	},
	{ "help",       no_argument,        NULL, 'H'	},
	{ }
};

int main(int argc, char *argv[])
{
	unsigned long flags = 0;

	int dumpfd;
	int i,j;
	char *config = NULL;

	while(1) {
		int opt;

		opt = getopt_long(argc, argv, "d:m:t:c:v", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'd':
			if(!strcmp(optarg, "none")) {
				timing = TIMING_NONE;
			} else if(!strcmp(optarg, "delta")) {
				timing = TIMING_DELTA;
			}
			break;
		case 'm':
			factor = atof(optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'c':
			config = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 'V':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'H':
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

	dumpseq.current = NULL;
	dumpseq.frames = NULL;
	flags |= DUMP_BTSNOOP;
	flags |= DUMP_VERBOSE;
	for(j = optind; j < argc; j++) {
		dumpfd = open(argv[j], O_RDONLY);
		if(dumpfd < 0) {
			perror("Failed to open dump file");
		}

		if(parse_dump(dumpfd, &dumpseq, flags) < 0) {
			fprintf(stderr, "Error parsing dump file\n");
			vhci_close();
			return 1;
		}
	}
	dumpseq.current = dumpseq.frames;
	calc_rel_ts(&dumpseq);

	/* init type config */
	for(i = 0; i < 12288; i++)
		type_cfg.cmd[i] = NULL;
	for(i = 0; i < 256; i++)
		type_cfg.evt[i] = NULL;
	type_cfg.acl = NULL;

	if(config != NULL) {
		if(parse_config(config, &dumpseq, &type_cfg, verbose)) {
			vhci_close();
			return 1;
		}
	}

	/* init emulator */
	btdev = btdev_create(0);
	btdev_set_send_handler(btdev, btdev_send, NULL);

	gettimeofday(&start, NULL);

	/*
	 * make sure we open the interface after parsing
	 * through all files so we can start without delay
	 */
	if((fd = vhci_open()) < 0) {
		perror("Failed to open VHCI interface");
		return 1;
	}

	printf("Running\n");

	process();

	delete_list();
	delete_type_cfg();
	vhci_close();
	printf("Terminating\n");

	return 0;
}
