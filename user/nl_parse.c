#include "nl_parse.h"
#include "nl_user.h"
#include "netlink_common.h"
#include <linux/if_link.h>
#include <stdio.h>
#include <string.h>

static const netdev_flag flag_list[] = { { IFF_UP, "UP" },
					 { IFF_BROADCAST, "BROADCAST" },
					 { IFF_DEBUG, "DEBUG" },
					 { IFF_LOOPBACK, "LOOPBACK" },
					 { IFF_POINTOPOINT, "POINTOPOINT" },
					 { IFF_NOARP, "NOARP" },
					 { IFF_PROMISC, "PROMISC" },
					 { IFF_MULTICAST, "MULTICAST" },
					 { IFF_ALLMULTI, "ALLMULTI" },
					 { IFF_MASTER, "MASTER" },
					 { IFF_SLAVE, "SLAVE" },
					 { IFF_PORTSEL, "PORTSEL" },
					 { IFF_AUTOMEDIA, "AUTOMEDIA" },
					 { IFF_DYNAMIC, "DYNAMIC" },
					 { IFF_RUNNING, "RUNNING" },
					 { IFF_NOTRAILERS, "NOTRAILERS" },
					 { 0, NULL } };

void print_netdev_flags(unsigned int flags)
{
	printf("<");
	const char *sep = "";
	for (int i = 0; flag_list[i].flag; i++) {
		if (flags & flag_list[i].flag) {
			printf("%s%s", sep, flag_list[i].name);
			sep = ",";
		}
	}
	printf(">");
}

void print_netdev_operstate(unsigned int operstate)
{
	printf(" state ");
	const char *states[] = { "UNKNOWN", "NOTPRESENT",
				 "DOWN",    "LOWERLAYERDOWN",
				 "TESTING", "DORMANT",
				 "UP" };
	printf("%s", states[operstate]);
}

int parse_into_netdev(struct netdev *dev, struct nlattr *nl_na, size_t rem)
{
	if (!nl_na || !dev) {
		LOG_ERROR("Null pointer input");
		return -1;
	}
	int dev_count = 0;
	while (rem >= sizeof(*nl_na) && dev_count <= MAX_NETDEV_COUNT) {
		if (nl_na->nla_type == NL_UTIL_A_NETDEV) {
			dev_count++;
			struct nlattr *pos = NLA_DATA(nl_na);
			int rem_nest = NLMSG_ALIGN(nl_na->nla_len) - NLA_HDRLEN;

			while (rem_nest >= sizeof(*pos)) {
				void *data = NLA_DATA(pos);
				switch (pos->nla_type) {
				case NL_UTIL_NESTED_A_IFINDEX:
					dev->ifindex = *(uint32_t *)data;
					break;
				case NL_UTIL_NESTED_A_IFNAME:
					strncpy(dev->ifname, data,
						IFNAMSIZ - 1);
					break;
				case NL_UTIL_NESTED_A_IFMTU:
					dev->mtu = *(uint32_t *)data;
					break;
				case NL_UTIL_NESTED_A_FLAGS:
					dev->flags = *(uint32_t *)data;
					break;
				case NL_UTIL_NESTED_A_STATE:
					dev->operstate = *(uint32_t *)data;
					break;
				case NL_UTIL_NESTED_A_QLEN:
					dev->qlen = *(uint32_t *)data;
					dev->initialized_fields |=
						NETDEV_QLEN_SET;
					break;
				case NL_UTIL_NESTED_A_IFMAC:
					memcpy(dev->ifmac, data, ETH_ALEN);
					break;
				case NL_UTIL_NESTED_A_IFBRD:
					memcpy(dev->ifbrd, data, MAX_ADDR_LEN);
					break;
				case NL_UTIL_NESTED_A_STATS:
					memcpy(&dev->stats, data,
					       sizeof(struct rtnl_link_stats64));
					dev->initialized_fields |=
						NETDEV_STATS_SET;
					break;
				default:
					LOG_ERROR("Unknown attr: %d",
						  pos->nla_type);
				}
				rem_nest -= NLA_ALIGN(pos->nla_len);
				pos = NLA_NEXT(pos);
			}
		}
		rem -= NLA_ALIGN(nl_na->nla_len);
		nl_na = NLA_NEXT(nl_na);
		dev++;
	}
	return dev_count;
}

int print_netdevs(struct netdev *netdev, int n)
{
	for (int i = 0; i < n; i++) {
		struct netdev *d = &netdev[i];
		printf("%d: %s: ", d->ifindex, d->ifname);
		print_netdev_flags(d->flags);
		printf(" mtu %d", d->mtu);
		print_netdev_operstate(d->operstate);
		if (d->initialized_fields & NETDEV_QLEN_SET) {
			printf(" qlen %d", d->qlen);
		}
		printf("\n    link/ether %02x:%02x:%02x:%02x:%02x:%02x brd %02x:%02x:%02x:%02x:%02x:%02x\n",
		       d->ifmac[0], d->ifmac[1], d->ifmac[2], d->ifmac[3],
		       d->ifmac[4], d->ifmac[5], d->ifbrd[0], d->ifbrd[1],
		       d->ifbrd[2], d->ifbrd[3], d->ifbrd[4], d->ifbrd[5]);
		if (d->initialized_fields & NETDEV_STATS_SET) {
			printf("rx packets %llu\n", d->stats.rx_packets);
			printf("rx errors %llu\n", d->stats.rx_errors);
			printf("rx bytes %llu\n", d->stats.rx_bytes);
			printf("tx packets %llu\n", d->stats.tx_packets);
			printf("tx errors %llu\n", d->stats.tx_errors);
			printf("tx bytes %llu\n", d->stats.tx_bytes);
		}
	}
	return 0;
}
