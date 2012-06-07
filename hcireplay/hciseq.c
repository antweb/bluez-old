#include <stdlib.h>
#include <stdint.h>
#include "hciseq.h"
#include "parser/parser.h"

int find_by_opcode(struct framenode *start, struct framenode **ptr, uint16_t opcode) {
	unsigned int pos;
	struct framenode *tmp;
	uint16_t opcode_next;

	pos = 1;
	tmp = start->next;
	while(tmp != NULL) {
		opcode_next = le16_to_cpu(tmp->frame->data+1);
		if(opcode == opcode_next) {
			*ptr = tmp;
			return pos;
		}
		tmp = tmp->next;
		pos++;
	}

	return -1;
}
