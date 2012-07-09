#ifndef HCISEQ_H
#define HCISEQ_H

#define le16_to_cpu(val) (val)
#define cpu_to_le16(val) (val)

enum hciseq_action {
	HCISEQ_ACTION_REPLAY = 0,
	HCISEQ_ACTION_EMULATE = 1,
	HCISEQ_ACTION_SKIP = 2
};

struct hciseq {
	struct hciseq_node *frames;
	struct hciseq_node *current;
	int len;
};

struct hciseq_attr {
	struct timeval ts_rel;
	struct timeval ts_diff;
	enum hciseq_action action;
};

struct hciseq_node {
	struct frame *frame;
	struct hciseq_node *next;
	struct hciseq_attr *attr;
};

int find_by_opcode(struct hciseq_node *start, struct hciseq_node **ptr, uint16_t opcode);
void calc_rel_ts();

#endif
