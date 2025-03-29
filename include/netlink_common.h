#pragma once

#define FAMILY_NAME "nl_ip_util"

/* attributes */
enum NL_UTIL_ATTRS {
  NL_UTIL_A_USPEC,
  NL_UTIL_A_NETDEV,
  __NL_UTIL_A_MAX
};
#define NL_UTIL_A_MAX (__NL_UTIL_A_MAX - 1)

/* nested attributes */
enum {
  NL_UTIL_NESTED_A_IFINDEX,
  NL_UTIL_NESTED_A_IFNAME,
  NL_UTIL_NESTED_A_IFMTU,
  NL_UTIL_NESTED_A_STATE,
  __NL_UTIL_NESTED_A_MAX
};
#define NL_UTIL_NESTED_A_MAX (__NL_UTIL_NESTED_A_MAX - 1)

/* commands */
enum NL_UTIL_CMDS {
  NL_UTIL_C_UNSPEC,
  NL_UTIL_C_L2_LIST,
  NL_UTIL_C_L2_IID,
  NL_UTIL_C_REPLY_WITH_NLMSG_ERR,
  __NL_UTIL_C_MAX
};
#define NL_UTIL_C_MAX (__NL_UTIL_C_MAX - 1)
