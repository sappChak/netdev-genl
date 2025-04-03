#include "netlink_common.h"
#include "nl_user.h"
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * struct nl_msg - Netlink message structure
 * @n: Netlink message header
 * @g: Generic netlink header
 * @buf: Buffer for attributes and payload
 */
struct nl_msg {
	struct nlmsghdr n; /* Netlink message header */
	struct genlmsghdr g; /* Generic netlink header */
	char buf[NL_MSG_BUF_SIZE]; /* Buffer for attributes and payload */
};

/**
 * struct nl_context - Netlink communication context
 * @fd: Netlink socket file descriptor
 * @fam_id: Netlink family ID
 * @nl_address: Netlink socket address
 * @req: Request message buffer
 * @res: Response message buffer
 */
struct nl_context {
	int fd; /* Netlink socket file descriptor */
	int fam_id; /* Netlink family ID */
	struct sockaddr_nl nl_address; /* Netlink socket address */
	struct nl_msg *req; /* Request message buffer */
	struct nl_msg *res; /* Response message buffer */
};

/**
 * main - Program entry point
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Returns: 0 on success, non-zero on failure
 */
int main(int argc, const char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s show [L2_IID]\n", argv[0]);
		return 1;
	}

	/* Initialize program context */
	struct nl_context *ctx = nl_context_init();
	if (!ctx) {
		perror("Failed to initialize context");
		return 1;
	}

	/* Open and bind netlink socket */
	if (open_and_bind(ctx) < 0) {
		nl_context_free(ctx);
		return 1;
	}

	/* Resolve family ID for communication */
	if (resolve_family_id_by_name(ctx, FAMILY_NAME) < 0) {
		perror("Failed to resolve family ID");
		nl_context_free(ctx);
		return 1;
	}

	/* Handle command line arguments */
	if (strcmp(argv[1], "show") == 0) {
		if (argc == 2) {
			handle_l2_list(ctx);
		} else if (argc == 3) {
			handle_l2_by_ifindex(ctx, atoi(argv[2]));
		} else {
			fprintf(stderr, "Usage: %s show [L2_IID]\n", argv[0]);
			nl_context_free(ctx);
			return 1;
		}
	} else {
		fprintf(stderr, "Usage: %s show [L2_IID]\n", argv[0]);
		nl_context_free(ctx);
		return 1;
	}

	nl_context_free(ctx);
	return 0;
}

/**
 * nl_context_init - Initialize netlink context
 *
 * Returns: Pointer to allocated context, NULL on failure
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
 * nl_context_free - Free netlink context resources
 * @ctx: Context to free
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
 * set_nl_addr - Configure netlink address structure
 * @ctx: Netlink context
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
 * open_and_bind - Create and bind netlink socket
 * @ctx: Netlink context
 *
 * Returns: 0 on success, -1 on failure
 */
int open_and_bind(struct nl_context *ctx)
{
	/* Create netlink socket */
	ctx->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (ctx->fd < 0) {
		perror("Failed to create socket");
		return -1;
	}

	/* Bind socket to address */
	memset(&ctx->nl_address, 0, sizeof(struct sockaddr_nl));
	ctx->nl_address.nl_family = AF_NETLINK;
	if (bind(ctx->fd, (struct sockaddr *)&ctx->nl_address,
		 sizeof(struct sockaddr_nl)) < 0) {
		perror("Failed to bind socket");
		close(ctx->fd);
		return -1;
	}

	return 0;
}

/**
 * resolve_family_id_by_name - Resolve netlink family ID by name
 * @ctx: Netlink context
 * @fam_name: Family name to resolve
 *
 * Returns: 0 on success, -1 on failure
 */
int resolve_family_id_by_name(struct nl_context *ctx, const char *fam_name)
{
	ssize_t rxtx_len;
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
		perror("Failed to send family ID request");
		return -1;
	}

	/* Receive response */
	res = set_res(ctx);
	rxtx_len = recv(ctx->fd, (char *)res, sizeof(*res), 0);
	if (rxtx_len < 0) {
		perror("Failed to receive family ID response");
		return -1;
	}

	/* Validate response */
	if (!NLMSG_OK((&res->n), rxtx_len)) {
		LOG_ERROR("Invalid response length for family ID request\n");
		return -1;
	}
	if (res->n.nlmsg_type == NLMSG_ERROR) {
		LOG_ERROR("Received error response for family ID request\n");
		return -1;
	}

	/* Parse family ID from response */
	na = (struct nlattr *)GENLMSG_DATA(res);
	if (na->nla_type == CTRL_ATTR_FAMILY_NAME) {
		LOG_INFO("Family name: %s\n", (char *)NLA_DATA(na));
	}
	na = (struct nlattr *)((char *)na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		ctx->fam_id = *(__u16 *)NLA_DATA(na);
	}

	return 0;
}

/**
 * set_req - Prepare a netlink request message
 * @ctx: Netlink context
 * @fam_id: Family ID
 * @cmd: Command to execute
 *
 * Returns: Pointer to prepared request message
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
 * Returns: Pointer to prepared response message
 */
struct nl_msg *set_res(struct nl_context *ctx)
{
	memset(ctx->res, 0, sizeof(struct nl_msg));
	return ctx->res;
}

/**
 * handle_l2_list - Request and process list of L2 interfaces
 * @ctx: Netlink context
 */
void handle_l2_list(struct nl_context *ctx)
{
	ssize_t rxtx_len;
	struct nlattr *na;
	struct nl_msg *req, *res;

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

	/* Parse response */
	na = (struct nlattr *)GENLMSG_DATA(res);
	int rem = GENLMSG_PAYLOAD(&res->n);
	parse_nl_util_response(na, rem);
}

/**
 * handle_l2_by_ifindex - Request and process interface info by index
 * @ctx: Netlink context
 * @ifindex: Interface index to query
 */
void handle_l2_by_ifindex(struct nl_context *ctx, const int ifindex)
{
	ssize_t rxtx_len;
	struct nlattr *na, *na_nested;
	struct nl_msg *req, *res;

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
	int rem = GENLMSG_PAYLOAD(&res->n);
	parse_nl_util_response(na, rem);
}

/**
 * parse_nl_util_response - Parse and display netlink response attributes
 * @nl_na: Netlink attribute to parse
 * @rem: Remaining bytes in message
 */
void parse_nl_util_response(struct nlattr *nl_na, int rem)
{
	while (rem >= sizeof(*nl_na)) {
		if (nl_na->nla_type == NL_UTIL_A_NETDEV) {
			struct nlattr *pos = (struct nlattr *)NLA_DATA(nl_na);
			int rem_nest = NLMSG_ALIGN(nl_na->nla_len) - NLA_HDRLEN;

			while (rem_nest >= sizeof(*pos)) {
				unsigned char *mac;
				switch (pos->nla_type) {
				case NL_UTIL_NESTED_A_IFINDEX:
					printf("%d: ", *(__u32 *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_IFNAME:
					printf("%s: ", (char *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_IFMTU:
					printf("mtu %d\n",
					       *(__u32 *)NLA_DATA(pos));
					break;
				case NL_UTIL_NESTED_A_IFMAC:
					mac = (__u8 *)NLA_DATA(pos);
					printf("link/ether: %02x:%02x:%02x:%02x:%02x:%02x\n",
					       mac[0], mac[1], mac[2], mac[3],
					       mac[4], mac[5]);
					break;
				default:
					LOG_INFO("Unknown attribute type: %d\n",
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
}
