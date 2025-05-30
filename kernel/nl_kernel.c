#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/genetlink.h>
#include <netlink_common.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrii Konotop <konotop401@gmail.com>");
MODULE_DESCRIPTION(
	"Kernel module that provides network interface information via Generic Netlink sockets to userspace");

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

int l2_list_doit(struct sk_buff *sender_buff, struct genl_info *info);
int l2_iid_doit(struct sk_buff *sender_buff, struct genl_info *info);
int nlmsg_err_doit(struct sk_buff *sender_buff, struct genl_info *info);
int put_nested_basic(struct sk_buff *reply_buff, struct net_device *netdev);
int put_nested_detailed(struct sk_buff *reply_buff, struct net_device *netdev);

struct nla_policy nl_util_nested_policy[NL_UTIL_NESTED_A_MAX + 1] = {
	[NL_UTIL_NESTED_A_IFINDEX] = { .type = NLA_U32 },
};

struct nla_policy nl_util_genl_policy[NL_UTIL_A_MAX + 1] = {
	[NL_UTIL_A_NETDEV] = NLA_POLICY_NESTED(nl_util_nested_policy),
};

struct genl_ops nl_util_gnl_ops[NL_UTIL_C_MAX] = {
	{
		.cmd = NL_UTIL_C_L2_LIST, /* Command to list L2 interfaces */
		.flags = 0, /* No special flags required */
		.internal_flags = 0, /* No internal flags needed */
		.doit = l2_list_doit, /* Callback handler for listing interfaces */
		.dumpit = NULL, /* No dump functionality implemented */
		.start = NULL, /* No start handler needed */
		.done = NULL, /* No completion handler needed */
		.validate = 0, /* Default validation */
	},
	{
		.cmd = NL_UTIL_C_L2_IID, /* Command to get interface by ID */
		.flags = 0, /* No special flags required */
		.internal_flags = 0, /* No internal flags needed */
		.doit = l2_iid_doit, /* Callback handler for interface lookup */
		.dumpit = NULL, /* No dump functionality implemented */
		.start = NULL, /* No start handler needed */
		.done = NULL, /* No completion handler needed */
		.validate = 0, /* Default validation */
	},
	{
		.cmd = NL_UTIL_C_REPLY_WITH_NLMSG_ERR, /* Command to return error message */
		.flags = 0, /* No special flags required */
		.internal_flags = 0, /* No internal flags needed */
		.doit = nlmsg_err_doit, /* Callback handler for error response */
		.dumpit = NULL, /* No dump functionality implemented */
		.start = NULL, /* No start handler needed */
		.done = NULL, /* No completion handler needed */
		.validate = 0, /* Default validation */
	}
};

static struct genl_family nl_util_genl_family = {
	.id = 0, /* Auto-assigned ID */
	.hdrsize = 0, /* No custom header */
	.name = FAMILY_NAME, /* Family name for userspace identification */
	.version = 1, /* Family version number */
	.ops = nl_util_gnl_ops, /* Array of operations */
	.n_ops = NL_UTIL_C_MAX, /* Number of operations */
	.policy = nl_util_genl_policy, /* Attribute validation policy */
	.maxattr = NL_UTIL_A_MAX, /* Maximum number of attributes */
	.module = THIS_MODULE, /* Owning kernel module */
};

int l2_list_doit(struct sk_buff *sender_buff, struct genl_info *info)
{
	struct net_device *netdev;
	struct sk_buff *reply_buff;
	void *msg_hdr;
	int rc;

	pr_info("Callback %s() invoked\n", __func__);

	if (info->attrs[NL_UTIL_A_UNSPEC]) {
		pr_info("Empty message received in %s()\n", __func__);
	}

	/* Allocate reply buffer */
	reply_buff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!reply_buff) {
		pr_err("Failed to allocate reply buffer\n");
		return -ENOMEM;
	}

	/* Initialize message header */
	msg_hdr = genlmsg_put(reply_buff, info->snd_portid, info->snd_seq + 1,
			      &nl_util_genl_family, 0, NL_UTIL_C_L2_LIST);
	if (!msg_hdr) {
		pr_err("Failed to allocate message header\n");
		nlmsg_free(reply_buff);
		return -ENOMEM;
	}

	/* Iterate through network devices */
	rcu_read_lock();
	for_each_netdev_rcu(&init_net, netdev) {
		pr_info("Found device with name: [%s]\n", netdev->name);
		if (netdev->type == ARPHRD_ETHER | ARPHRD_LOOPBACK) {
			struct nlattr *start = nla_nest_start_noflag(
				reply_buff, NL_UTIL_A_NETDEV);
			if (!start) {
				pr_err("Failed to start nested attribute\n");
				nlmsg_free(reply_buff);
				rcu_read_unlock();
				return -ENOMEM;
			}
			/* Add interface attributes */
			if (put_nested_basic(reply_buff, netdev)) {
				pr_err("Failed to add nested attributes\n");
				nla_nest_cancel(reply_buff, start);
				nlmsg_free(reply_buff);
				rcu_read_unlock();
				return -ENOMEM;
			}
			nla_nest_end(reply_buff, start);
		}
	}
	rcu_read_unlock();

	/* Finalize the message */
	genlmsg_end(reply_buff, msg_hdr);

	/* Send the response */
	rc = genlmsg_unicast(genl_info_net(info), reply_buff, info->snd_portid);
	if (rc) {
		pr_err("Failed to send message in %s(): %d\n", __func__, rc);
		return -rc;
	}

	return 0;
}

int l2_iid_doit(struct sk_buff *sender_buff, struct genl_info *info)
{
	struct net_device *netdev;
	struct sk_buff *reply_buff;
	struct nlattr *na, *na_nested;
	void *msg_hdr;
	int ifindex;
	int rc;

	pr_info("Callback %s() invoked\n", __func__);

	na = info->attrs[NL_UTIL_A_NETDEV];
	if (!na) {
		pr_err("Missing required attribute in %s()\n", __func__);
		return -EINVAL;
	}

	/* Allocate reply buffer */
	reply_buff = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!reply_buff) {
		pr_err("Failed to allocate reply buffer\n");
		return -ENOMEM;
	}

	/* Initialize message header */
	msg_hdr = genlmsg_put(reply_buff, info->snd_portid, info->snd_seq + 1,
			      &nl_util_genl_family, 0, NL_UTIL_C_L2_IID);
	if (!msg_hdr) {
		pr_err("Failed to allocate message header\n");
		nlmsg_free(reply_buff);
		return -ENOMEM;
	}

	/* Extract interface index from payload */
	na_nested = (struct nlattr *)nla_data(na);
	ifindex = nla_get_u32(na_nested);
	if (!ifindex) {
		pr_err("Failed to obtain interface index from payload\n");
		nlmsg_free(reply_buff);
		return -EINVAL;
	}

	/* Get network device by index */
	rcu_read_lock();
	netdev = dev_get_by_index_rcu(&init_net, ifindex);
	if (!netdev) {
		pr_err("Failed to obtain network device for index %d\n",
		       ifindex);
		rcu_read_unlock();
		nlmsg_free(reply_buff);
		return -ENODEV;
	}

	/* Start nested attribute for response */
	struct nlattr *start =
		nla_nest_start_noflag(reply_buff, NL_UTIL_A_NETDEV);
	if (!start) {
		pr_err("Failed to start nested attribute\n");
		rcu_read_unlock();
		nlmsg_free(reply_buff);
		return -ENOMEM;
	}

	/* Add interface attributes */
	if (put_nested_detailed(reply_buff, netdev)) {
		pr_err("Failed to add nested attributes\n");
		nla_nest_cancel(reply_buff, start);
		rcu_read_unlock();
		nlmsg_free(reply_buff);
		return -ENOMEM;
	}

	nla_nest_end(reply_buff, start);
	rcu_read_unlock();

	/* Finalize the message */
	genlmsg_end(reply_buff, msg_hdr);

	/* Send the response */
	rc = genlmsg_unicast(genl_info_net(info), reply_buff, info->snd_portid);
	if (rc) {
		pr_err("Failed to send message in %s(): %d\n", __func__, rc);
		return -rc;
	}

	return 0;
}

int nlmsg_err_doit(struct sk_buff *sender_buff, struct genl_info *info)
{
	pr_info("Callback %s() invoked, sending NLMSG_ERR response\n",
		__func__);
	return -EINVAL;
}

int put_nested_basic(struct sk_buff *reply_buff, struct net_device *netdev)
{
	if (nla_put_u32(reply_buff, NL_UTIL_NESTED_A_IFINDEX,
			netdev->ifindex) ||
	    nla_put_string(reply_buff, NL_UTIL_NESTED_A_IFNAME, netdev->name) ||
	    nla_put_u32(reply_buff, NL_UTIL_NESTED_A_FLAGS, netdev->flags) ||
	    nla_put_u32(reply_buff, NL_UTIL_NESTED_A_IFMTU, netdev->mtu) ||
	    nla_put_u32(reply_buff, NL_UTIL_NESTED_A_QLEN,
			netdev->tx_queue_len) ||
	    nla_put_u32(reply_buff, NL_UTIL_NESTED_A_STATE,
			netdev->operstate) ||
	    nla_put(reply_buff, NL_UTIL_NESTED_A_IFMAC, ETH_ALEN,
		    netdev->dev_addr) ||
	    nla_put(reply_buff, NL_UTIL_NESTED_A_IFBRD, ETH_ALEN,
		    netdev->broadcast)) {
		return -1;
	}
	return 0;
}

int put_nested_detailed(struct sk_buff *reply_buff, struct net_device *netdev)
{
	struct rtnl_link_stats64 stats;
	if (put_nested_basic(reply_buff, netdev)) {
		return -1;
	}
	dev_get_stats(netdev, &stats);
	if (nla_put(reply_buff, NL_UTIL_NESTED_A_STATS, sizeof(stats),
		    &stats)) {
		return -1;
	}
	return 0;
}

static int __init netlink_mod_init(void)
{
	int rc;
	pr_info("Initializing module\n");

	rc = genl_register_family(&nl_util_genl_family);
	if (rc) {
		pr_err("Failed to register family: %d\n", rc);
		return rc;
	}

	pr_info("Successfully registered family '%s'\n", FAMILY_NAME);
	return 0;
}

static void __exit netlink_mod_exit(void)
{
	int rc;
	pr_info("Unloading module\n");

	rc = genl_unregister_family(&nl_util_genl_family);
	if (rc) {
		pr_err("Failed to unregister family: %d\n", rc);
		return;
	}

	pr_info("Successfully unregistered family '%s'\n", FAMILY_NAME);
}

module_init(netlink_mod_init);
module_exit(netlink_mod_exit);
