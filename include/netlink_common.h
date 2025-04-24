#pragma once

/* Common definitions for the nl_util Generic Netlink family */

/* Name of the Generic Netlink family for utility operations */
#ifndef FAMILY_NAME
#define FAMILY_NAME "nl_util"
#endif

/* Top-level attributes for nl_ip_util messages */
enum NL_UTIL_ATTRS {
	NL_UTIL_A_UNSPEC, /* Unspecified attribute (placeholder) */
	NL_UTIL_A_NETDEV, /* Network device-related attributes */
	__NL_UTIL_A_MAX /* Internal max value for validation */
};
#define NL_UTIL_A_MAX (__NL_UTIL_A_MAX - 1)

/* Nested attributes for network device information under NL_UTIL_A_NETDEV */
enum NL_UTIL_NESTED_ATTRS {
	NL_UTIL_NESTED_A_UNSPEC, /* Unspecified nested attribute (placeholder) */
	NL_UTIL_NESTED_A_IFINDEX, /* Interface index (e.g., 2 for eth0) */
	NL_UTIL_NESTED_A_IFNAME, /* Interface name (e.g., "eth0") */
	NL_UTIL_NESTED_A_FLAGS, /* Interface flags (e.g., up/down) */
	NL_UTIL_NESTED_A_IFMTU, /* Interface MTU (maximum transmission unit) */
	NL_UTIL_NESTED_A_STATE, /* Interface operational state (e.g., up/down) */
	NL_UTIL_NESTED_A_QLEN, /* Interface TX queue length */
	NL_UTIL_NESTED_A_STATS, /* Interface statistics (e.g., RX/TX bytes) */
	NL_UTIL_NESTED_A_IFBRD, /* Interface broadcast address */
	NL_UTIL_NESTED_A_IFMAC, /* Interface MAC address */
	__NL_UTIL_NESTED_A_MAX /* Internal max value for validation */
};
#define NL_UTIL_NESTED_A_MAX (__NL_UTIL_NESTED_A_MAX - 1)

/* Commands supported by the nl_ip_util family */
enum NL_UTIL_CMDS {
	NL_UTIL_C_UNSPEC, /* Unspecified command (placeholder) */
	NL_UTIL_C_L2_LIST, /* List all Layer 2 network interfaces */
	NL_UTIL_C_L2_IID, /* Query a Layer 2 interface by index */
	NL_UTIL_C_REPLY_WITH_NLMSG_ERR, /* Reply with an NLMSG_ERROR (for testing?) */
	__NL_UTIL_C_MAX /* Internal max value for validation */
};
#define NL_UTIL_C_MAX (__NL_UTIL_C_MAX - 1)
