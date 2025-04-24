#pragma once

#include <linux/netlink.h>
#include <linux/genetlink.h>

#define NL_MSG_BUF_SIZE 4096

/* --- Netlink Parsing Macros --- */
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_NEXT(na) \
	((struct nlattr *)((char *)(na) + NLA_ALIGN((na)->nla_len)))

/* --- Logging Utilities --- */
#define LOG_INFO(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/* --- Initial Config Setup Functions --- */
struct nl_context *nl_context_init(void);
void nl_context_free(struct nl_context *ctx);
int open_and_bind(struct nl_context *ctx);
int resolve_family_id_by_name(struct nl_context *ctx, const char *fam_name);

/* --- Core Functionality --- */
int handle_l2_list(struct nl_context *ctx);
int handle_l2_by_ifindex(struct nl_context *ctx, const int ifindex);

/* --- Utility Functions --- */
struct nl_msg *set_req(struct nl_context *ctx, const int fam_id, const int cmd);
struct nl_msg *set_res(struct nl_context *ctx);
