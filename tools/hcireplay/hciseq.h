#ifndef HCISEQ_H
#define HCISEQ_H

#define le16_to_cpu(val) (val)
#define cpu_to_le16(val) (val)

enum hciseq_action {
	HCISEQ_ACTION_REPLAY = 0,
	HCISEQ_ACTION_EMULATE = 1
};

struct hciseq {
	struct framenode *frames;
	struct framenode *current;
	int len;
};

struct hciseq_attr {
	struct timeval ts_rel;
	struct timeval ts_diff;
	enum hciseq_action action;
};

struct framenode {
	struct frame *frame;
	struct framenode *next;
	struct hciseq_attr *attr;
};

int find_by_opcode(struct framenode *start, struct framenode **ptr, uint16_t opcode);
void calc_rel_ts();

#endif
