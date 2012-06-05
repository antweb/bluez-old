/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include "mainloop.h"
#include "server.h"
#include "vhci.h"

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "hcireplay.h"
#include "parser/parser.h"
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

struct hciseq dumpseq;

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

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		delete_list();
		mainloop_quit();
		break;
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

static int parse_dump(int fd, struct hciseq *dumpseq, unsigned long flags)
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
			dumpseq->frames = nodeptr;
			nodeptr->next = NULL;
			last = nodeptr;
		} else {
			last->next = nodeptr;
			last = nodeptr;
		}
		dumpseq->len = ++count;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct vhci *vhci;
	struct server *server;
	sigset_t mask;

	int fd;

	unsigned long flags = 0;
	unsigned long filter = ~0L;
	int device = 0;
	int defpsm = 0;
	int defcompid = DEFAULT_COMPID;
	int opt, pppdump_fd = -1, audio_fd = -1;
	uint16_t obex_port;

	mainloop_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_callback, NULL, NULL);

	vhci = vhci_open(VHCI_TYPE_BREDR, 0x23);
	if (!vhci) {
		fprintf(stderr, "Failed to open Virtual HCI device\n");
		return 1;
	}

	fd = open("test.btsnoop", O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Error opening dump file\n");
		perror("err");
	}

	flags |= DUMP_BTSNOOP;
	if(parse_dump(fd, &dumpseq, flags) < 0) {
		fprintf(stderr, "Error parsing dump file\n");
		vhci_close(vhci);
		return 1;
	}
	btdev_set_hciseq(vhci->btdev, &dumpseq);

	server = server_open_unix("/tmp/bt-server-bredr", 0x42);
	if (!server) {
		fprintf(stderr, "Failed to open server channel\n");
		vhci_close(vhci);
		return 1;
	}

	return mainloop_run();
}
