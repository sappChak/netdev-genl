#include "nl_user.h"
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "netlink_common.h"
#include "nl_parse.h"

/**
 * struct nl_msg - Represents a Netlink message
 * @n: Netlink message header
 * @g: Generic Netlink message header
 * @buf: Payload and attribute buffer
 */
struct nl_msg {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[NL_MSG_BUF_SIZE];
};

/**
 * struct nl_context - Holds Netlink communication state
 * @fd: Socket file descriptor
 * @fam_id: Generic Netlink family ID
 * @nl_address: Address for Netlink socket
 * @req: Outgoing message buffer
 * @res: Incoming message buffer
 */
struct nl_context {
	int fd;
	int fam_id;
	struct sockaddr_nl nl_address;
	struct nl_msg *req;
	struct nl_msg *res;
};

/**
 * main - Entry point for Netlink utility
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Usage: <program> show [IFINDEX]
 *
 * Return: 0 on success, non-zero on failure
 */
int main(int argc, const char *argv[])
{
	if (argc < 2 || strcmp(argv[1], "show") != 0) {
		fprintf(stderr, "Usage: %s show [L2_IID]\n", argv[0]);
		return 1;
	}

	/* Initialize program context */
	struct nl_context *ctx = nl_context_init();
	if (!ctx) {
		return 1;
	}

	/* Open and bind netlink socket */
	if (open_and_bind(ctx) < 0) {
		nl_context_free(ctx);
		return -1;
	}

	/* Resolve family ID for communication */
	if (resolve_family_id_by_name(ctx, FAMILY_NAME) < 0) {
		nl_context_free(ctx);
		return -1;
	}

	/* Handle command line arguments */
	argc == 2 ? handle_l2_list(ctx) :
		    handle_l2_by_ifindex(ctx, atoi(argv[2]));

	nl_context_free(ctx);
	return 0;
}

/**
 * nl_context_init - Allocate and initialize context
 *
 * Return: Pointer to context or NULL on failure
 */
struct nl_context *nl_context_init(void)
{
	struct nl_context *ctx = calloc(1, sizeof(struct nl_context));
	if (!ctx) {
		perror("Failed to allocate context");
		return NULL;
	}
	ctx->fam_id = -1;
	ctx->fd = -1;
	ctx->req = calloc(1, sizeof(struct nl_msg));
	ctx->res = calloc(1, sizeof(struct nl_msg));
	if (!ctx->req || !ctx->res) {
		perror("Failed to allocate message buffers");
		free(ctx->req);
		free(ctx->res);
		free(ctx);
		return NULL;
	}
	return ctx;
}

/**
 * nl_context_free - Release resources in context
 * @ctx: Pointer to context
 */
void nl_context_free(struct nl_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->fd >= 0) {
		close(ctx->fd);
	}
	free(ctx->req);
	free(ctx->res);
	free(ctx);
}

/**
 * nl_context_free - Free netlink context resources
 * @ctx: Context to free
 */
void set_nl_addr(struct nl_context *ctx)
{
	memset(&ctx->nl_address, 0, sizeof(struct sockaddr_nl));
	ctx->nl_address.nl_family = AF_NETLINK;
	ctx->nl_address.nl_groups = 0; /* No multicast groups */
	ctx->nl_address.nl_pid = 0; /* Kernel PID */
	ctx->nl_address.nl_pad = 0;
}

/**
 * open_and_bind - Create and bind Netlink socket
 * @ctx: Netlink context
 *
 * Return: 0 on success, -1 on failure
 */
int open_and_bind(struct nl_context *ctx)
{
	/* Create netlink socket */
	ctx->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (ctx->fd < 0) {
		LOG_ERROR("Failed to create socket");
		return -1;
	}

	/* Bind socket to address */
	memset(&ctx->nl_address, 0, sizeof(struct sockaddr_nl));
	ctx->nl_address.nl_family = AF_NETLINK;
	if (bind(ctx->fd, (struct sockaddr *)&ctx->nl_address,
		 sizeof(struct sockaddr_nl)) < 0) {
		LOG_ERROR("Failed to bind socket");
		close(ctx->fd);
		return -1;
	}

	return 0;
}

/**
 * resolve_family_id_by_name - Get family ID for given name
 * @ctx: Netlink context
 * @fam_name: Name of the family
 *
 * Return: 0 on success, -1 on failure
 */
int resolve_family_id_by_name(struct nl_context *ctx, const char *fam_name)
{
	int rxtx_len;
	struct nlattr *na;
	struct nl_msg *req, *res;

	/* Prepare request message */
	req = set_req(ctx, GENL_ID_CTRL, CTRL_CMD_GETFAMILY);
	na = (struct nlattr *)GENLMSG_DATA(req);
	na->nla_len = strlen(fam_name) + 1 + NLA_HDRLEN;
	na->nla_type = CTRL_ATTR_FAMILY_NAME;
	strcpy(NLA_DATA(na), fam_name);
	req->n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* Send request */
	set_nl_addr(ctx);
	rxtx_len = sendto(ctx->fd, (char *)req, req->n.nlmsg_len, 0,
			  (struct sockaddr *)&ctx->nl_address,
			  sizeof(struct sockaddr_nl));
	if (rxtx_len != req->n.nlmsg_len) {
		LOG_ERROR("Failed to send family ID request");
		return -1;
	}

	/* Receive response */
	res = set_res(ctx);
	rxtx_len = recv(ctx->fd, (char *)res, sizeof(*res), 0);
	if (rxtx_len < 0) {
		LOG_ERROR("Failed to receive family ID response");
		return -1;
	}

	/* Validate response */
	if (!NLMSG_OK((&res->n), rxtx_len)) {
		LOG_ERROR("Invalid response length for family ID request\n");
		return -1;
	}
	if (res->n.nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(&res->n);
		LOG_ERROR("Error code: %d: %s\n", -err->error,
			  strerror(-err->error));
		return -1;
	}

	/* Parse family ID from response */
	na = (struct nlattr *)GENLMSG_DATA(res);
	na = (struct nlattr *)((char *)na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		ctx->fam_id = *(__u16 *)NLA_DATA(na);
	}

	return 0;
}

/**
 * set_req - Initialize Netlink request message
 * @ctx: Netlink context
 * @fam_id: Family ID
 * @cmd: Command ID
 *
 * Return: Pointer to request message
 */
struct nl_msg *set_req(struct nl_context *ctx, const int fam_id, const int cmd)
{
	memset(ctx->req, 0, sizeof(struct nl_msg));
	ctx->req->n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	ctx->req->n.nlmsg_type = fam_id;
	ctx->req->n.nlmsg_flags = NLM_F_REQUEST;
	ctx->req->n.nlmsg_seq = 0;
	ctx->req->n.nlmsg_pid = getpid();
	ctx->req->g.cmd = cmd;
	ctx->req->g.version = 0x1;
	return ctx->req;
}

/**
 * set_res - Prepare response buffer
 * @ctx: Netlink context
 *
 * Return: Pointer to response buffer
 */
struct nl_msg *set_res(struct nl_context *ctx)
{
	memset(ctx->res, 0, sizeof(struct nl_msg));
	return ctx->res;
}

/**
 * handle_l2_list - Query and display all L2 interfaces
 * @ctx: Netlink context
 */
void handle_l2_list(struct nl_context *ctx)
{
	int rxtx_len, dev_count;
	size_t rem;
	struct nlattr *na;
	struct nl_msg *req, *res;
	struct netdev *dev;

	/* Prepare and send request */
	req = set_req(ctx, ctx->fam_id, NL_UTIL_C_L2_LIST);
	set_nl_addr(ctx);
	rxtx_len = sendto(ctx->fd, (char *)req, req->n.nlmsg_len, 0,
			  (struct sockaddr *)&ctx->nl_address,
			  sizeof(struct sockaddr_nl));
	if (rxtx_len != req->n.nlmsg_len) {
		LOG_ERROR("Failed to send L2 list request\n");
		return;
	}

	/* Receive response */
	res = set_res(ctx);
	rxtx_len = recv(ctx->fd, (char *)res, sizeof(*res), 0);
	if (rxtx_len < 0) {
		perror("Failed to receive L2 list response");
		return;
	}

	/* Validate response */
	if (!NLMSG_OK((&res->n), rxtx_len)) {
		LOG_ERROR("Invalid L2 list response length\n");
		return;
	}
	if (res->n.nlmsg_type == NLMSG_ERROR) {
		LOG_ERROR("Received error in L2 list response\n");
		return;
	}
	if (res->n.nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(&res->n);
		LOG_ERROR("L2 list response: Error code: %d: %s\n", -err->error,
			  strerror(-err->error));
		return;
	}

	/* Parse response */
	na = (struct nlattr *)GENLMSG_DATA(res);
	rem = GENLMSG_PAYLOAD(&res->n);
	dev = (struct netdev *)malloc(MAX_NETDEV_SIZE * sizeof(struct netdev));
	if ((dev_count = parse_into_netdev(dev, na, rem)) <= 0) {
		LOG_ERROR("Failed to parse interface query response\n");
		free(dev);
		return;
	}
	print_netdevs(dev, dev_count);
	free(dev);
}

/**
 * handle_l2_by_ifindex - Query interface by index
 * @ctx: Netlink context
 * @ifindex: Interface index to query
 */
void handle_l2_by_ifindex(struct nl_context *ctx, const int ifindex)
{
	int rxtx_len, dev_count;
	size_t rem;
	struct nlattr *na, *na_nested;
	struct nl_msg *req, *res;
	struct netdev *dev;

	/* Prepare request with nested attribute */
	req = set_req(ctx, ctx->fam_id, NL_UTIL_C_L2_IID);
	set_nl_addr(ctx);
	na = (struct nlattr *)GENLMSG_DATA(req);
	na->nla_type = NLA_F_NESTED | NL_UTIL_A_NETDEV;
	na->nla_len = NLA_HDRLEN;
	na_nested = (struct nlattr *)NLA_DATA(na);
	na_nested->nla_type = NL_UTIL_NESTED_A_IFINDEX;
	na_nested->nla_len = NLA_HDRLEN + sizeof(int);
	*(int *)NLA_DATA(na_nested) = ifindex;
	na->nla_len += NLA_ALIGN(na_nested->nla_len);
	req->n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* Send request */
	rxtx_len = sendto(ctx->fd, (char *)req, req->n.nlmsg_len, 0,
			  (struct sockaddr *)&ctx->nl_address,
			  sizeof(struct sockaddr_nl));
	if (rxtx_len != req->n.nlmsg_len) {
		LOG_ERROR("Failed to send interface query request\n");
		return;
	}

	/* Receive response */
	res = set_res(ctx);
	rxtx_len = recv(ctx->fd, (char *)res, sizeof(*res), 0);
	if (rxtx_len < 0) {
		LOG_ERROR("Failed to receive interface query response\n");
		return;
	}

	/* Validate response */
	if (!NLMSG_OK((&res->n), rxtx_len)) {
		LOG_ERROR("Invalid interface query response length\n");
		return;
	}
	if (res->n.nlmsg_type == NLMSG_ERROR) {
		LOG_ERROR("Received error in interface query response\n");
		return;
	}

	/* Parse response */
	na = (struct nlattr *)GENLMSG_DATA(res);
	rem = GENLMSG_PAYLOAD(&res->n);
	dev = (struct netdev *)malloc(MAX_NETDEV_SIZE * sizeof(struct netdev));
	if ((dev_count = parse_into_netdev(dev, na, rem)) < 0) {
		LOG_ERROR("Failed to parse interface query response\n");
		free(dev);
		return;
	}
	print_netdevs(dev, dev_count);
	free(dev);
}
