#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/genetlink.h>
#include <netlink_common.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrii Konotop konotop401@gmail.com");
MODULE_DESCRIPTION("Kernel module which provides network interface information "
                   "using generic netlink sockets to user-space.");

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

int l2_list_doit(struct sk_buff *sender_buff, struct genl_info *info);
int l2_iid_doit(struct sk_buff *sender_buff, struct genl_info *info);
int nlmsg_err_doit(struct sk_buff *sender_buff, struct genl_info *info);

/* attribute policy */
struct nla_policy nl_util_genl_policy[NL_UTIL_A_MAX + 1] = {
    [NL_UTIL_A_USPEC] = {.type = NLA_UNSPEC},
    [NL_UTIL_A_IFINDEX] = {.type = NLA_U32},
};

/* operation defenition */
struct genl_ops nl_util_gnl_ops[NL_UTIL_C_MAX] = {
    {
        /* cmd on which the cb'll be triggered */
        .cmd = NL_UTIL_C_L2_LIST,
        /* TODO Use case ? */
        .flags = 0,
        /* TODO Use case ? */
        .internal_flags = 0,
        /* callback handler */
        .doit = l2_list_doit,
        /* no dumping here */
        .dumpit = NULL,
        // in a real application you probably have different .start handlers per
        // operation/command
        .start = NULL,
        // in a real application you probably have different .done handlers per
        // operation/command
        .done = NULL,
        .validate = 0,
    },
    {
        /* cmd on which the cb'll be triggered */
        .cmd = NL_UTIL_C_L2_IID,
        /* TODO Use case ? */
        .flags = 0,
        /* TODO Use case ? */
        .internal_flags = 0,
        /* callback handler */
        .doit = l2_iid_doit,
        /* no dumping here */
        .dumpit = NULL,
        // in a real application you probably have different .start handlers per
        // operation/command
        .start = NULL,
        // in a real application you probably have different .done handlers per
        // operation/command
        .done = NULL,
        .validate = 0,
    },
    {
        .cmd = NL_UTIL_C_REPLY_WITH_NLMSG_ERR,
        .flags = 0,
        .internal_flags = 0,
        .doit = nlmsg_err_doit,
        // .dumpit is not required, only optional; application
        // specific/dependent on your use case in a real application you
        // probably have different .dumpit handlers per operation/command
        .dumpit = NULL,
        // in a real application you probably have different .start handlers per
        // operation/command
        .start = NULL,
        // in a real application you probably have different .done handlers per
        // operation/command
        .done = NULL,
        .validate = 0,
    }};

/* family defention */
static struct genl_family nl_util_genl_family = {
    // automatically assign an id
    .id = 0,
    // we don't use custom additional header info / user specific header
    .hdrsize = 0,
    // The name of this family, used by userspace application to get the numeric
    // ID
    .name = FAMILY_NAME,
    // family specific version number; can be used to evolve application over
    // time (multiple versions)
    .version = 1,
    // delegates all incoming requests to callback functions
    .ops = nl_util_gnl_ops,
    // length of the commands array
    .n_ops = NL_UTIL_C_MAX,
    // attribute policy (for validation of messages). Enforced automatically,
    // except ".validate" in
    // corresponding ".ops"-field is set accordingly.
    .policy = nl_util_genl_policy,
    // Number of attributes / bounds check for policy (array length)
    .maxattr = NL_UTIL_A_MAX,
    // Owning Kernel module of the Netlink family we register.
    .module = THIS_MODULE,
};

int l2_list_doit(struct sk_buff *sender_buff, struct genl_info *info) {
  struct net_device *netdev;
  struct sk_buff *reply_buff;
  void *msg_hdr;
  int rc;

  pr_info("callback %s() is invoked ", __func__);

  if (info->attrs[NL_UTIL_A_USPEC]) {
    pr_info("empty message received in %s()\n", __func__);
  }

  /* allocate a new buffer for the reply */
  reply_buff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
  if (reply_buff == NULL) {
    pr_err("error allocating reply_buff\n");
    return -ENOMEM;
  }

  msg_hdr = genlmsg_put(reply_buff, info->snd_portid, info->snd_seq + 1,
                        &nl_util_genl_family, 0, NL_UTIL_C_L2_LIST);
  if (msg_hdr == NULL) {
    pr_err("error allocating memory for genl message header\n");
    nlmsg_free(reply_buff);
    return -ENOMEM;
  }

  // locking is handled automatically
  for_each_netdev(&init_net, netdev) {
    pr_info("found a device: [%s]\n", netdev->name);
    rc = nla_put_string(reply_buff, NL_UTIL_A_IFNAME, netdev->name);
    if (rc < 0) {
      pr_err("failed to add an attribute\n");
      nlmsg_free(reply_buff);
      return rc;
    }
  }

  /* fininalize the message */
  genlmsg_end(reply_buff, msg_hdr);

  /* send the message */
  rc = genlmsg_unicast(genl_info_net(info), reply_buff, info->snd_portid);
  if (rc != 0) {
    pr_err("an error occurred in %s():\n", __func__);
    return -rc;
  }

  return 0;
}

int l2_iid_doit(struct sk_buff *sender_buff, struct genl_info *info) {
  return 0;
}

int nlmsg_err_doit(struct sk_buff *sender_buff, struct genl_info *info) {
  pr_info("%s() invoked, a NLMSG_ERR response will be sent back\n", __func__);
  return -EINVAL;
}

static int __init netlink_mod_init(void) {
  int rc;
  pr_info("initting module\n");

  // Register family with its operations and policies
  rc = genl_register_family(&nl_util_genl_family);
  if (rc != 0) {
    pr_err("FAILED: genl_register_family(): %i\n", rc);
    pr_err("an error occurred while inserting the generic netlink example "
           "module\n");
    return -1;
  } else {
    pr_info("successfully registered custom Netlink family '" FAMILY_NAME
            "' using Generic Netlink.\n");
  }

  return 0;
}

static void __exit netlink_mod_exit(void) {
  int ret;
  pr_info("generic netlink example module unloaded.\n");

  // Unregister the family
  ret = genl_unregister_family(&nl_util_genl_family);
  if (ret != 0) {
    pr_err("genl_unregister_family() failed: %i\n", ret);
    return;
  } else {
    pr_info("successfully unregistered custom netlink family '" FAMILY_NAME
            "' using generic netlink.\n");
  }
}

module_init(netlink_mod_init);
module_exit(netlink_mod_exit);
