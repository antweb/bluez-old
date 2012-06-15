#ifndef HCISEQ_H
#define HCISEQ_H

#define le16_to_cpu(val) (val)
#define cpu_to_le16(val) (val)

struct hciseq {
	struct framenode *frames;
	struct framenode *current;
	int len;
};

struct framenode {
	struct frame *frame;
	struct framenode *next;
	struct timeval ts_rel;
};

int find_by_opcode(struct framenode *start, struct framenode **ptr, uint16_t opcode);

#endif
