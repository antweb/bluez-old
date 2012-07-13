#ifndef HCIREPLAY_H
#define HCIREPLAY_H

#include "hciseq.h"

struct hcidump_hdr {
	uint16_t len;
	uint8_t in;
	uint8_t pad;
	uint32_t ts_sec;
	uint32_t ts_usec;
} __attribute__ ((packed));
#define HCIDUMP_HDR_SIZE (sizeof(struct hcidump_hdr))

struct btsnoop_hdr {
	uint8_t id[8];		/* Identification Pattern */
	uint32_t version;	/* Version Number = 1 */
	uint32_t type;		/* Datalink Type */
} __attribute__ ((packed));
#define BTSNOOP_HDR_SIZE (sizeof(struct btsnoop_hdr))

struct btsnoop_pkt {
	uint32_t size;		/* Original Length */
	uint32_t len;		/* Included Length */
	uint32_t flags;		/* Packet Flags */
	uint32_t drops;		/* Cumulative Drops */
	uint64_t ts;		/* Timestamp microseconds */
	uint8_t data[0];	/* Packet Data */
} __attribute__ ((packed));
#define BTSNOOP_PKT_SIZE (sizeof(struct btsnoop_pkt))

static uint8_t btsnoop_id[] = { 0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00 };

static uint32_t btsnoop_version = 0;
static uint32_t btsnoop_type = 0;

struct pktlog_hdr {
	uint32_t len;
	uint64_t ts;
	uint8_t type;
} __attribute__ ((packed));
#define PKTLOG_HDR_SIZE (sizeof(struct pktlog_hdr))

/* Parser flags */
#define DUMP_WIDTH	20

#define DUMP_ASCII	0x0001
#define DUMP_HEX	0x0002
#define DUMP_EXT	0x0004
#define DUMP_RAW	0x0008
#define DUMP_BPA	0x0010
#define DUMP_TSTAMP	0x0100
#define DUMP_VERBOSE	0x0200
#define DUMP_BTSNOOP	0x1000
#define DUMP_PKTLOG	0x2000
#define DUMP_NOVENDOR	0x4000
#define DUMP_TYPE_MASK	(DUMP_ASCII | DUMP_HEX | DUMP_EXT)

struct frame {
	void *data;
	uint32_t data_len;
	void *ptr;
	uint32_t len;
	uint16_t dev_id;
	uint8_t in;
	uint8_t master;
	uint16_t handle;
	uint16_t cid;
	uint16_t num;
	uint8_t dlci;
	uint8_t channel;
	unsigned long flags;
	struct timeval ts;
	int pppdump_fd;
	int audio_fd;
};

struct hciseq_type_cfg {
	struct hciseq_attr *cmd[12288];
	struct hciseq_attr *evt[256];
	struct hciseq_attr *acl;
};

__useconds_t timeval_diff(struct timeval *l, struct timeval *r,
			  struct timeval *diff);

#endif
