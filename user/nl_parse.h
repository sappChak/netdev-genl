#pragma once

#include <linux/netlink.h>
#include <stddef.h>

typedef struct {
	unsigned int flag;
	const char *name;
} netdev_flag;

int parse_nl_util_response(struct nlattr *nl_na, size_t rem);
