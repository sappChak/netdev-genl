#pragma once

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_NETDEV_COUNT 32

typedef struct {
	unsigned int flag;
	const char *name;
} netdev_flag;

struct netdev {
	unsigned int ifindex;
	char ifname[IFNAMSIZ];
	unsigned int flags;
	unsigned int mtu;
	unsigned int operstate;
	unsigned int qlen;
	uint8_t ifmac[ETH_ALEN];
	uint8_t ifbrd[MAX_ADDR_LEN];
	struct rtnl_link_stats64 stats;
	unsigned int initialized_fields;
};

#define NETDEV_QLEN_SET (1 << 0)
#define NETDEV_STATS_SET (1 << 1)

int parse_into_netdev(struct netdev *dev, struct nlattr *nl_na, size_t rem);
int print_netdevs(struct netdev *netdev, int n);
