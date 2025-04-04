#include "nl_parse.h"
#include <linux/if.h>
#include <stdio.h>
#include <stdint.h>
#include "nl_user.h"
#include "netlink_common.h"

// impl Display for netdev_flag {}
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

/**
 * parse_netdev_flags - Parse and display network device flags
 * @flags: Flags to parse
 *
 * This function takes a set of flags and prints their names in a human-readable
 * format. The flags are defined in the netdev_flag structure.
 */
void parse_netdev_flags(unsigned int flags)
{
	printf("<");
	int comma = 0;
	for (int i = 0; flag_list[i].flag != 0; i++) {
		if (flags & flag_list[i].flag) {
			if (comma) {
				printf(",");
			}
			printf("%s", flag_list[i].name);
			comma = 1;
		}
	}
	printf(">");
}

/**
 * parse_nl_util_response - Parse and display netlink response attributes for network devices
 * @nl_na: Pointer to the netlink attribute to parse (must not be NULL)
 * @rem: Remaining bytes in the message 
 * Returns: 0 on success, negative value on error
 */
int parse_nl_util_response(struct nlattr *nl_na, size_t rem)
{
	if (!nl_na) {
		return -1;
	}
	while (rem >= sizeof(*nl_na)) {
		if (nl_na->nla_type == NL_UTIL_A_NETDEV) {
			struct nlattr *pos = (struct nlattr *)NLA_DATA(nl_na);
			int rem_nest = NLMSG_ALIGN(nl_na->nla_len) - NLA_HDRLEN;

			while (rem_nest >= sizeof(*pos)) {
				uint8_t *mac, *brd;
				switch (pos->nla_type) {
				case NL_UTIL_NESTED_A_IFINDEX:
					printf("%d:",
					       *(uint32_t *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_IFNAME:
					printf(" %s:", (char *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_IFMTU:
					printf(" mtu %d",
					       *(uint32_t *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_FLAGS:
					parse_netdev_flags(
						*(uint32_t *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_STATE:
					printf(" state %s\n",
					       (char *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_IFMAC:
					mac = (uint8_t *)NLA_DATA(pos);
					printf("    link/ether %02x:%02x:%02x:%02x:%02x:%02x",
					       mac[0], mac[1], mac[2], mac[3],
					       mac[4], mac[5]);
					break;
				case NL_UTIL_NESTED_A_IFBRD:
					brd = (uint8_t *)NLA_DATA(pos);
					printf(" brd: %02x:%02x:%02x:%02x:%02x:%02x\n",
					       brd[0], brd[1], brd[2], brd[3],
					       brd[4], brd[5]);
					break;
				default:
					LOG_ERROR(
						"Unknown attribute type: %d\n",
						pos->nla_type);
				}
				rem_nest -= NLA_ALIGN(pos->nla_len);
				pos = (struct nlattr *)((char *)pos +
							NLA_ALIGN(
								pos->nla_len));
			}
		}
		rem -= NLA_ALIGN(nl_na->nla_len);
		nl_na = (struct nlattr *)((char *)nl_na +
					  NLA_ALIGN(nl_na->nla_len));
	}

	return 0;
}
