#include "netlink_common.h"
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// get a pointer to the first attribute in the Generic Netlink message.
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))

// get the total length of the attributes in the Generic Netlink message.
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)

// get a pointer to the data part of a Netlink attribute.
#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))

int open_and_bind();
int resolve_family_id_by_name(const char *fam_name);
void handle_l2_list();
void handle_l2_by_iid(const char *ifidx);
void parse_nl_util_response(struct nlattr *nl_na, int rem);

int nl_fd;                     // netlink socket's file descriptor
struct sockaddr_nl nl_address; // netlink address
int nl_family_id = -1;
int nl_rxtx_length;   // sent/received length
struct nlattr *nl_na; // netlink attributes

struct {
  struct nlmsghdr n;
  struct genlmsghdr g;
  char buf[256];
} nl_request_msg, nl_response_msg;

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s show <L2_IID>\n", argv[0]);
    return 1;
  }

  if (open_and_bind() < 0) {
    return -1;
  }

  if (resolve_family_id_by_name(FAMILY_NAME) < 0) {
    perror("resolve_family_by_name");
    close(nl_fd);
    return -1;
  }

  // parse commands
  if (strcmp(argv[1], "show") == 0 && argc == 2) {
    handle_l2_list();
  } else if (strcmp(argv[1], "show") == 0 && argc == 3) {
    handle_l2_by_iid(argv[2]);
  } else {
    fprintf(stderr, "Usage: ./%s show <L2_IID>\n", argv[0]);
    close(nl_fd);
    return 1;
  }

  close(nl_fd);
  return 0;
}

int open_and_bind() {
  // create generic netlink socket
  nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (nl_fd < 0) {
    perror("socket()");
    return -1;
  }

  // bind the socket to nl_address
  memset(&nl_address, 0, sizeof(nl_address));
  nl_address.nl_family = AF_NETLINK;

  if (bind(nl_fd, (struct sockaddr *)&nl_address, sizeof(nl_address)) < 0) {
    perror("bind()");
    return -1;
  }

  return 0;
}

// nlmsghdr -> genlmsghdr -> nl_attrs -> payload
int resolve_family_id_by_name(const char *fam_name) {
  nl_request_msg.n.nlmsg_len =
      NLMSG_LENGTH(GENL_HDRLEN); // total length of the msg
  nl_request_msg.n.nlmsg_type = GENL_ID_CTRL;
  nl_request_msg.n.nlmsg_flags = NLM_F_REQUEST; // it's a request
  nl_request_msg.n.nlmsg_seq = 0;
  nl_request_msg.n.nlmsg_pid = getpid();
  nl_request_msg.g.cmd = CTRL_CMD_GETFAMILY;
  nl_request_msg.g.version = 0x1;

  // populate the payload's "netlink attributes"
  nl_na = (struct nlattr *)GENLMSG_DATA(&nl_request_msg);
  nl_na->nla_len =
      strlen(fam_name) + 1 + NLA_HDRLEN; // header + data(family name)
  nl_na->nla_type = CTRL_ATTR_FAMILY_NAME;
  strcpy(NLA_DATA(nl_na), fam_name);

  /* align if the attribute isn't a multiple of 4(padding) */
  nl_request_msg.n.nlmsg_len += NLMSG_ALIGN(nl_na->nla_len);

  memset(&nl_address, 0, sizeof(nl_address));
  nl_address.nl_family = AF_NETLINK;
  nl_address.nl_groups = 0; // we don't use multicast groups
  nl_address.nl_pid = 0;    // kernel pid is 0
  nl_address.nl_pad = 0;

  // send the family id request message to the netlink controller
  nl_rxtx_length =
      sendto(nl_fd, (char *)&nl_request_msg, nl_request_msg.n.nlmsg_len, 0,
             (struct sockaddr *)&nl_address, sizeof(nl_address));
  if (nl_rxtx_length != nl_request_msg.n.nlmsg_len) {
    perror("sendto()");
    return -1;
  }

  // receive reply from the kernel
  nl_rxtx_length =
      recv(nl_fd, (char *)&nl_response_msg, sizeof(nl_response_msg), 0);
  if (nl_rxtx_length < 0) {
    perror("recv()");
    return -1;
  }

  // Validate response message
  if (!NLMSG_OK((&nl_response_msg.n), nl_rxtx_length)) {
    fprintf(stderr, "family ID request : invalid message\n");
    fprintf(stderr,
            "error validating family id request result: invalid length\n");
    return -1;
  }
  if (nl_response_msg.n.nlmsg_type == NLMSG_ERROR) { // error
    fprintf(stderr, "family ID request : receive error\n");
    fprintf(stderr,
            "error validating family id request result: receive error\n");
    return -1;
  }

  // Extract family name
  nl_na = (struct nlattr *)GENLMSG_DATA(&nl_response_msg);
  if (nl_na->nla_type == CTRL_ATTR_FAMILY_NAME) {
    printf("family name is: %s\n", (char *)NLA_DATA(nl_na));
  }

  /* shift the pointer. CTRL_ATTR_FAMILY_NAME -> CTRL_ATTR_FAMILY_ID */
  nl_na = (struct nlattr *)((char *)nl_na + NLA_ALIGN(nl_na->nla_len));

  if (nl_na->nla_type == CTRL_ATTR_FAMILY_ID) {
    nl_family_id = *(__u16 *)NLA_DATA(nl_na);
  }

  printf("family id is: %d\n", nl_family_id);

  return 0;
}

void handle_l2_list() {
  memset(&nl_request_msg, 0, sizeof(nl_request_msg));
  memset(&nl_response_msg, 0, sizeof(nl_response_msg));

  nl_request_msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  nl_request_msg.n.nlmsg_type = nl_family_id;
  nl_request_msg.n.nlmsg_flags = NLM_F_REQUEST;
  nl_request_msg.n.nlmsg_seq = 0; // no need to split messages
  nl_request_msg.n.nlmsg_pid = getpid();
  nl_request_msg.g.cmd = NL_UTIL_C_L2_LIST;
  nl_request_msg.g.version = 1;

  memset(&nl_address, 0, sizeof(nl_address));
  nl_address.nl_family = AF_NETLINK;
  nl_address.nl_groups = 0; // we don't use multicast groups
  nl_address.nl_pid = 0;    // kernel pid is 0
  nl_address.nl_pad = 0;

  nl_rxtx_length =
      sendto(nl_fd, (char *)&nl_request_msg, nl_request_msg.n.nlmsg_len, 0,
             (struct sockaddr *)&nl_address, sizeof(nl_address));
  if (nl_rxtx_length != nl_request_msg.n.nlmsg_len) {
    perror("not everything was send: sendto()");
    return;
  }

  nl_rxtx_length =
      recv(nl_fd, (char *)&nl_response_msg, sizeof(nl_response_msg), 0);
  if (nl_rxtx_length < 0) {
    perror("recv()");
    return;
  }

  // validate response message
  if (!NLMSG_OK((&nl_response_msg.n), nl_rxtx_length)) {
    fprintf(stderr, "NL_UTIL_C_L2_LIST request : invalid message\n");
    fprintf(
        stderr,
        "error validating NL_UTIL_C_L2_LIST request result: invalid length\n");
  }
  if (nl_response_msg.n.nlmsg_type == NLMSG_ERROR) {
    fprintf(stderr, "NL_UTIL_C_L2_LIST request : receive error\n");
    fprintf(
        stderr,
        "error validating NL_UTIL_C_L2_LIST request result: receive error\n");
  }

  // parse the response
  nl_na = (struct nlattr *)GENLMSG_DATA(&nl_response_msg);
  int rem = GENLMSG_PAYLOAD(&nl_response_msg.n);
  parse_nl_util_response(nl_na, rem);
}

void handle_l2_by_iid(const char *ifidx) {}

// nlmsghdr -> genlmsghdr -> NL_UTIL_A_NETDEV -> (nested attrs) ->
// NL_UTIL_A_NETDEV -> (nested_attrs) -> ...
void parse_nl_util_response(struct nlattr *nl_na, int rem) {
  while (rem >= sizeof(*nl_na)) {
    if (nl_na->nla_type == NL_UTIL_A_NETDEV) {
      struct nlattr *pos = (struct nlattr *)NLA_DATA(nl_na);
      int rem_nest = NLMSG_ALIGN(nl_na->nla_len) - NLA_HDRLEN;

      while (rem_nest >= sizeof(*pos)) {
        switch (pos->nla_type) {
        case NL_UTIL_NESTED_A_IFINDEX:
          printf("%d: ", *(__u32 *)NLA_DATA(pos));
          break;
        case NL_UTIL_NESTED_A_IFNAME:
          printf("%s: ", (char *)NLA_DATA(pos));
          break;
        case NL_UTIL_NESTED_A_IFMTU:
          printf("mtu %d\n", *(__u32 *)NLA_DATA(pos));
          break;
        default:
          printf("unknown attribute received\n");
        }
        rem_nest -= NLA_ALIGN(pos->nla_len);
        // go to the next nested device
        pos = (struct nlattr *)((char *)pos + NLA_ALIGN(pos->nla_len));
      }
    }

    rem -= NLA_ALIGN(nl_na->nla_len);
    // go to the next device
    nl_na = (struct nlattr *)((char *)nl_na + NLA_ALIGN(nl_na->nla_len));
  }
}
