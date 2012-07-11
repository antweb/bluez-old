#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/time.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "hciseq.h"
#include "hcireplay.h"
#include "monitor/bt.h"

#define MAXLINE 128

struct hciseq *seq;
struct hciseq_type_cfg *type_cfg;

static bool verbose;
static int line;

struct scope_list {
	struct scope_node *head;
};

struct scope_node {
	int pos;
	struct hciseq_attr *attr;
	struct scope_node *next;
};

struct attr_list {
	struct attr_node *head;
};

struct attr_node {
	char key[32];
	char val[32];
	struct attr_node *next;
};

static void attr_list_delete(struct attr_list *list) {
	struct attr_node *node, *next;

	if(list == NULL)
		return;

	node = list->head;
	free(list);
	while(node != NULL) {
		next = node->next;
		free(node);
		node = next;
	}
}

static void scope_list_delete(struct scope_list *list) {
	struct scope_node *node, *next;

	if(list == NULL)
		return;

	node = list->head;
	free(list);
	while(node != NULL) {
		next = node->next;
		free(node);
		node = next;
	}
}

static struct attr_list* parse_attrstr(char *attrstr) {
	struct attr_list *list = NULL;
	struct attr_node *node;
	char *res;

	do {
		if(list == NULL) {
			if((res = strtok(attrstr, "=")) == NULL) {
				/* nothing to parse */
				return NULL;
			}

			list = (struct attr_list*) malloc(sizeof(struct attr_list));
			node = (struct attr_node*) malloc(sizeof(struct attr_node));
			list->head = node;
		} else {
			if((res = strtok(NULL, "=")) == NULL) {
				/* nothing left to parse */
				break;
			}

			node->next = (struct attr_node*) malloc(sizeof(struct attr_node));
			node = node->next;
		}

		strncpy(node->key, res, 32);
		node->key[31] = '\0';

		if((res =strtok(NULL, ",")) == NULL) {
			fprintf(stderr, "Invalid attribute");
			goto err;
		}
		strncpy(node->val, res, 32);
		node->key[31] = '\0';

		node->next = NULL;
	} while(res != NULL);

	return list;

err:
	attr_list_delete(list);
	return NULL;
}

static int apply_attr(struct scope_node *scope_node, struct attr_list *list) {
	struct attr_node *attr_node = list->head;
	struct hciseq_attr *attr = scope_node->attr;
	long lval;

	while(attr_node != NULL) {
		if(strcmp(attr_node->key, "delta") == 0) {
			/* delta */
			lval = strtol(attr_node->val, NULL, 10);
			if(errno == ERANGE || errno == EINVAL) {
				return 1;
			}

			if(verbose) {
				printf("\t[%d] set delta to %ld\n", scope_node->pos, lval);
			}

			attr->ts_diff.tv_sec = 0;
			attr->ts_diff.tv_usec = lval;
		} else if(strcmp(attr_node->key, "action") == 0) {
			/* action */
			if(strcmp(attr_node->val, "replay") == 0) {
				lval = HCISEQ_ACTION_REPLAY;
				if(verbose) {
					printf("\t[%d] set action to 'replay'\n", scope_node->pos);
				}
			} else if(strcmp(attr_node->val, "emulate") == 0) {
				lval = HCISEQ_ACTION_EMULATE;
				if(verbose) {
					printf("\t[%d] set action to 'emulate'\n", scope_node->pos);
				}
			} else if(strcmp(attr_node->val, "skip") == 0) {
				lval = HCISEQ_ACTION_SKIP;
				if(verbose) {
					printf("\t[%d] set action to 'skip'\n", scope_node->pos);
				}
			} else {
				return 1;
			}

			attr->action = lval;
		}

		attr_node = attr_node->next;
	}

	return 0;
}

static int apply_attr_scope(struct scope_list *scope, struct attr_list *attr) {
	struct scope_node *node = scope->head;

	while(node != NULL) {
		apply_attr(node, attr);
		node = node->next;
	}

	return 0;
}

static struct scope_list* get_scope_range(int from, int to) {
	struct scope_list *list = NULL;
	struct scope_node *scope_node;
	struct hciseq_node *seq_node = seq->current;
	int pos = 1;


	/* forward to 'from' */
	while(pos < from) {
		seq_node = seq_node->next;
		pos++;
	}

	/* create scope list for range */
	while(pos <= to) {
		if(verbose) {
			printf("\tadd packet [%d]\n", pos);
		}

		if(list == NULL) {
			list = (struct scope_list*) malloc(sizeof(struct scope_list));
			scope_node = (struct scope_node*) malloc(sizeof(struct scope_node));
			list->head = scope_node;
		} else {
			scope_node->next = (struct scope_node*) malloc(sizeof(struct scope_node));
			scope_node = scope_node->next;
		}
		scope_node->attr = seq_node->attr;
		scope_node->pos = pos;
		scope_node->next = NULL;

		seq_node = seq_node->next;
		pos++;
	}

	return list;

err:
	scope_list_delete(list);
	return NULL;
}

static struct scope_list* get_scope_type(uint8_t type, void *filter1, void *filter2) {
	struct scope_list *list = NULL;
	struct scope_node *scope_node;
	struct hciseq_node *seq_node = seq->current;
	uint16_t opcode, node_opcode;
	uint8_t ogf, node_ogf;
	uint16_t ocf, node_ocf;
	uint8_t evt, node_evt;
	bool match;
	int pos = 1;
	struct hciseq_attr *attr;

	if(type == BT_H4_CMD_PKT) {
		ogf = *((uint8_t*)filter1);
		ocf = *((uint16_t*)filter2);
		opcode = cmd_opcode_pack(ogf, ocf);

		if(opcode > 0x2FFF) {
			attr = NULL;
		} else {
			attr = type_cfg->cmd[opcode];
			if(attr == NULL) {
				attr = (struct hciseq_attr*) malloc(sizeof(struct hciseq_attr));
				type_cfg->cmd[opcode] = attr;
			}
		}
	} else if(type == BT_H4_EVT_PKT) {
		evt = *((uint8_t*)filter1);
		attr = type_cfg->evt[evt];

		if(attr == NULL) {
			attr = (struct hciseq_attr*) malloc(sizeof(struct hciseq_attr));
			type_cfg->evt[evt] = attr;
		}
	} else if(type == BT_H4_ACL_PKT) {
		attr = type_cfg->acl;
		if(attr == NULL) {
			attr = (struct hciseq_attr*) malloc(sizeof(struct hciseq_attr));
			type_cfg->acl = attr;
		}
	}

	/* add matching packets in sequence */
	while(seq_node != NULL) {
		match = false;
		if(((uint8_t*)seq_node->frame->data)[0] == type) {
			if(type == BT_H4_CMD_PKT) {
				node_opcode = *((uint16_t*) (seq_node->frame->data+1));
				node_ogf = cmd_opcode_ogf(node_opcode);
				node_ocf = cmd_opcode_ocf(node_opcode);
				if(node_ogf == ogf && node_ocf == ocf)
					match = true;
			} else if(type == BT_H4_EVT_PKT) {
				node_evt = ((uint8_t*)seq_node->frame->data)[1];
				if(evt == node_evt)
					match = true;
			} else if(type == BT_H4_ACL_PKT) {
				match = true;
			}
		}

		if(match) {
			if(verbose) {
				printf("\tadd packet [%d]\n", pos);
			}
			if(list == NULL) {
				list = (struct scope_list*) malloc(sizeof(struct scope_list));
				scope_node = (struct scope_node*) malloc(sizeof(struct scope_node));
				list->head = scope_node;
			} else {
				scope_node->next = (struct scope_node*) malloc(sizeof(struct scope_node));
				scope_node = scope_node->next;
			}
			scope_node->attr = seq_node->attr;
			scope_node->pos = pos;
			scope_node->next = NULL;
		}
		seq_node = seq_node->next;
		pos++;
	}

	/* add type config */
	if(attr != NULL) {
		if(list == NULL) {
			list = (struct scope_list*) malloc(sizeof(struct scope_list));
			scope_node = (struct scope_node*) malloc(sizeof(struct scope_node));
			list->head = scope_node;
		} else {
			scope_node->next = (struct scope_node*) malloc(sizeof(struct scope_node));
			scope_node = scope_node->next;
		}

		scope_node->attr = attr;
		scope_node->pos = 0;
		scope_node->next = NULL;
	}

	return list;
}

static int parse_line(char *buf) {
	char *scopestr, *attrstr;
	struct scope_list *scope_list;
	struct attr_list *attr_list;
	char substr[4];
	unsigned int tmp;
	uint8_t evt, ogf;
	uint16_t ocf;
	char *res;
	int from, to;

	line++;

	/* split line into scope and attributes */
	if((scopestr = strtok(buf, " ")) == NULL) {
		return 1;
	}
	if((attrstr = strtok(NULL, "\n")) == NULL) {
		return 1;
	}

	if(verbose) {
		printf("Parsing scope (%s)\n", scopestr);
	}

	strncpy(substr, scopestr, 3);
	substr[3] = '\0';

	if(strcmp(scopestr, "all") == 0) {
		if(verbose)
			printf("\tadd all\n");

		scope_list = get_scope_range(0, seq->len);
	} else if((strcmp(substr, "HCI") == 0) && strlen(scopestr) >= 7) {
		/* make sure scopestr is at least 7 chars long, so we can check for HCI_XXX */

		strncpy(substr, scopestr + 4, 3);
		substr[3] = '\0';
		if(strcmp(substr, "ACL") == 0) {
			/* scope is HCI_ACL */
			if(verbose)
				printf("\tadd all HCI ACL data packets:");

			scope_list = get_scope_type(BT_H4_ACL_PKT, NULL, NULL);
		} else if(strcmp(substr, "CMD") == 0) {
			/* scope is HCI_CMD_
			 * length must be exactly 19 (e.g. HCI_CMD_0x03|0x0003) */
			if(strlen(scopestr) != 19 || scopestr[12] != '|')
				return 1;

			if(sscanf(scopestr + 8,"0x%2x", &tmp) <= 0)
				return 1;
			ogf = (uint8_t)tmp;

			if(sscanf(scopestr + 13,"0x%4x", &tmp) <= 0)
				return 1;
			ocf = (uint16_t)tmp;

			if(verbose)
				printf("\tadd all HCI command packets with opcode (0x%2.2x|0x%4.4x):\n", ogf, ocf);

			scope_list = get_scope_type(BT_H4_CMD_PKT, &ogf, &ocf);
		} else if(strcmp(substr, "EVT") == 0) {
			/* scope is CMD_EVT_
			 * length must be exactly 12 (e.g. HCI_EVT_0x0e) */
			if(strlen(scopestr) != 12)
				return 1;
			if(sscanf(scopestr + 8,"0x%2x", &tmp) <= 0)
				return 1;

			evt = (uint8_t)tmp;

			if(verbose)
				printf("\tadd all HCI event packets with event type (0x%2.2x):\n", evt);

			scope_list = get_scope_type(BT_H4_EVT_PKT, &evt, NULL);
		}
	} else if(scopestr[0] >= 48 || scopestr[0] <=57) {
		/* first char is a digit */
		if((res = strtok(scopestr, "-")) == NULL) {
			return 1;
		}
		from = atoi(res);
		if(from <= 0) {
			return 1;
		}

		if((res = strtok(NULL, ":")) == NULL) {
			/* just one packet */
			if(verbose)
				printf("\tadd packet single packet\n");

			scope_list = get_scope_range(from, from);
		} else {
			/* range */
			to = atoi(res);
			if(to > seq->len) {
				return 1;
			}

			if(verbose)
				printf("\tadd packets %d to %d\n", from, to);

			scope_list = get_scope_range(from, to);
		}

	}

	if(verbose)
		printf("Parsing attributes (%s)\n", attrstr);

	if((attr_list = parse_attrstr(attrstr)) == NULL) {
		return 1;
	}

	if(scope_list != NULL) {
		apply_attr_scope(scope_list, attr_list);
		scope_list_delete(scope_list);
	} else {
		if(verbose)
			printf("Empty scope, skipping\n");
	}

	attr_list_delete(attr_list);

	return 0;
}

int parse_config(char *path, struct hciseq *_seq, struct hciseq_type_cfg *_type_cfg, bool _verbose) {
	char *buf;
	FILE* file;

	seq = _seq;
	type_cfg = _type_cfg;
	verbose = _verbose;
	line = 0;

	printf("Reading config file...\n");

	buf = (char*) malloc(sizeof(char) * MAXLINE);

	if((file = fopen(path, "r")) == NULL) {
		perror("Failed to open config file");
		return 1;
	}
	while (fgets(buf, MAXLINE, file) != NULL) {
		if(parse_line(buf)) {
			fprintf(stderr, "Error parsing config file - line %d\n", line);
			free(buf);
			return 1;
		}
	}

	printf("Done\n\n");
	free(buf);
	return 0;
}

