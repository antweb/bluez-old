#include <stdlib.h>
#include <stdint.h>
#include "hciseq.h"
#include "main.h"
#include "monitor/bt.h"

int find_by_opcode(struct hciseq_node *start, struct hciseq_node **ptr,
		   uint16_t opcode)
{
	unsigned int pos;
	struct hciseq_node *tmp;
	uint16_t opcode_next;

	pos = 1;
	tmp = start->next;
	while (tmp != NULL) {
		if (((uint8_t *) tmp->frame->data)[0] == BT_H4_CMD_PKT) {
			opcode_next = le16_to_cpu(
					*((uint16_t *) (tmp->frame->data + 1)));
			if (opcode == opcode_next) {
				*ptr = tmp;
				return pos;
			}
		}
		tmp = tmp->next;
		pos++;
	}

	return -1;
}

void calc_rel_ts(struct hciseq *seq)
{
	struct timeval start;
	struct hciseq_node *tmp;

	start = seq->current->frame->ts;
	tmp = seq->current;

	/* first packet */
	tmp->attr->ts_rel.tv_sec = 0;
	tmp->attr->ts_rel.tv_usec = 0;
	tmp->attr->ts_diff.tv_sec = 0;
	tmp->attr->ts_diff.tv_usec = 0;

	while (tmp->next != NULL) {
		timeval_diff(&tmp->next->frame->ts, &start,
			     &tmp->next->attr->ts_rel);
		timeval_diff(&tmp->next->frame->ts, &tmp->frame->ts,
			     &tmp->next->attr->ts_diff);
		tmp = tmp->next;
	}
}
