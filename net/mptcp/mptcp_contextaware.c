#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/genetlink.h>


#include <linux/netlink.h>
#include <linux/genetlink.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/mptcp_v6.h>
#endif

#define CA_PM_GENL_VERSION 1
#define CA_PM_GROUP_NAME "CA_PM_GROUP"
#define CA_PM_FAMILY_NAME "CA_PM_FAMILY"
#define CA_PM_GENL_HDRLEN	0

int recv_genl_context(struct sk_buff *skb, struct genl_info *info);
static void context_create_subflows(struct sock *meta_sk);

typedef enum {
	CONTEXT_CMD_CREATE_SUBFLOW,
	CONTEXT_CMD_REMOVE_SUBFLOW,
	CONTEXT_CMD_MOD_SUBFLOW,
	__CONTEXT_RECV_CMD_MAX
} E_CONTEXT_RECV_CMD;

typedef enum {
    CONTEXT_CMD_REGISTER_SESSION,
    CONTEXT_CMD_REMOVE_SESSION,
    __CONTEXT_SEND_CMD_MAX
} E_CONTEXT_SEND_CMD;

typedef enum {
    CONTEXT_ATTR_UNSPEC,
    CONTEXT_DST_PORT,
    CONTEXT_SRC_ADDR,
    CONTEXT_DST_ADDR,
    CONTEXT_LOC_ID,
    CONTEXT_MPTCP_TOKEN,
    __CONTEXT_MAX
} E_CONTEXT_ATTRIB ;

static struct genl_family context_genl_family = {
    .id = GENL_ID_GENERATE,
    .hdrsize = CA_PM_GENL_HDRLEN,
    .name = CA_PM_FAMILY_NAME,
    .version = CA_PM_GENL_VERSION,
    .maxattr = __CONTEXT_MAX
};

static struct nla_policy context_genl_policy[__CONTEXT_MAX] = {
   [CONTEXT_DST_PORT] = { .type = NLA_U16},
   [CONTEXT_SRC_ADDR] = { .type = NLA_U32},
   [CONTEXT_DST_ADDR] = { .type = NLA_U32},
   [CONTEXT_MPTCP_TOKEN] = { .type = NLA_U32}
};

static struct genl_multicast_group mptcp_context_multicast_group[1] =
{
	{
    	.name = CA_PM_GROUP_NAME
	}
};

static struct genl_ops context_genl_ops[__CONTEXT_RECV_CMD_MAX] = {
	{
	    .cmd = CONTEXT_CMD_CREATE_SUBFLOW,
	    .policy = context_genl_policy,
	    .doit = recv_genl_context
	},
	{
		.cmd = CONTEXT_CMD_REMOVE_SUBFLOW,
		.policy = context_genl_policy,
		.doit = recv_genl_context
	},
	{
		.cmd = CONTEXT_CMD_MOD_SUBFLOW,
		.policy = context_genl_policy,
		.doit = recv_genl_context
	}
};

enum {
        SUBFLOW_MOD_ADD = 0x01,
        SUBFLOW_MOD_DEL = 0x00,
};


struct subflow_mod {
    struct list_head list;
    u32 token;
    u32 daddr;
    u32 saddr;
    u16 dport;
	u32 locid;
    u8 action;
};

struct context_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;
	struct work_struct remove_work;
    struct work_struct register_work;
	struct mptcp_cb *mpcb;

    struct list_head flowmods;
};


void remove_session_from_daemon(struct work_struct *work)
{
    struct context_priv *pm_priv = container_of(work, struct context_priv, remove_work);
    struct mptcp_cb *mpcb = pm_priv->mpcb;
    struct sock *meta_sk = mpcb->meta_sk;
    struct sk_buff *skb = 0;
    int rc = 0;
    void *msg_head;
    u32 token = 0;

    mpcb = tcp_sk(meta_sk)->mpcb;
    token = mpcb->mptcp_loc_token;

    mptcp_debug("%s sending request to userspace token: %04x\n", __func__, token);

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

    if (skb == NULL) {
        mptcp_debug("%s could not allocate space for new msg\n", __func__);
        return;
    }

    msg_head = genlmsg_put(
                    skb,
                    0,            /* pid  */
                    0, /* no de seq (NL_AUTO_SEQ ne marche pas) */
                    &context_genl_family,
                    CA_PM_GENL_HDRLEN,    /* header length (to check) */
                    CONTEXT_CMD_REMOVE_SESSION   /* command */
                );

    if (msg_head == NULL) {
        mptcp_debug("%s could not create generic header\n", __func__);
        return;
    }

    rc = nla_put_u32(skb, CONTEXT_MPTCP_TOKEN, token);
    if (rc != 0) {
        mptcp_debug("%s could not add token \n", __func__);
        return;
    }

    genlmsg_end(skb, msg_head);

    rc = genlmsg_multicast(
            &context_genl_family,
            skb,
            0,
            0,
            GFP_KERNEL
        );

    if(rc != 0) {
        mptcp_debug("%s could not multicast packet to group, error [%d]\n", __func__, rc);

        /* no such process */
        if (rc == -ESRCH) {
            mptcp_debug("%s Should be because daemon is not running\n", __func__);
        }
        return;
    }
    mptcp_debug("%s Successfully multicasted\n", __func__);
    return;
}

void register_session_with_daemon(struct work_struct *work)
{
    struct context_priv *pm_priv = container_of(work, struct context_priv, register_work);

    struct mptcp_cb *mpcb = pm_priv->mpcb;
    struct sock *meta_sk = mpcb->meta_sk;
    struct sk_buff *skb = 0;
    int rc = 0;
    void *msg_head;
    struct in_addr *daddr = 0;
    struct in_addr *saddr = 0;
    u32 token = 0;
    u32 eid = 0;
    u16 dport = 0;

    mpcb = tcp_sk(meta_sk)->mpcb;
    daddr = (struct in_addr *)&inet_sk(meta_sk)->inet_daddr;
    saddr = (struct in_addr *)&inet_sk(meta_sk)->inet_saddr;
    eid = daddr->s_addr;
    dport = inet_sk(meta_sk)->inet_dport;
    token = mpcb->mptcp_loc_token;

    mptcp_debug("%s sending request to userspace %pI4 (src: %pI4) token: %04x\n", __func__, &eid, saddr, token);

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

    if (skb == NULL) {
        mptcp_debug("%s could not allocate space for new msg\n", __func__);
        return;
    }

    msg_head = genlmsg_put(
				skb,
				0,            /* pid  */
				0, /* no de seq (NL_AUTO_SEQ ne marche pas) */
				&context_genl_family,
				CA_PM_GENL_HDRLEN,    /* header length (to check) */
				CONTEXT_CMD_REGISTER_SESSION   /* command */
			);

    if (msg_head == NULL) {
        mptcp_debug("%s could not create generic header\n", __func__);
        return;
    }

    rc = nla_put_u32(skb, CONTEXT_MPTCP_TOKEN, token);
    if (rc != 0) {
        mptcp_debug("%s could not add token: %04x \n", __func__, token);
        return;
    }
    
    mptcp_debug("%s added token: %04x \n", __func__, token);

    rc = nla_put_u32(skb, CONTEXT_DST_ADDR, eid);
    if (rc != 0){
    	mptcp_debug("%s could not add destination address \n", __func__);
        return;
    }

    rc = nla_put_u32(skb, CONTEXT_DST_PORT, dport);
    if (rc != 0){
        mptcp_debug("%s could not add destination port \n", __func__);
        return;
    }

    rc = nla_put_u32(skb, CONTEXT_SRC_ADDR, saddr->s_addr);
    if (rc != 0){
        mptcp_debug("%s could not add source address \n", __func__);
        return;
    }

    genlmsg_end(skb, msg_head);

    rc = genlmsg_multicast(
                &context_genl_family,
	        skb,
	        0,
	        0,
	        GFP_KERNEL
    	);

    if(rc != 0) {
        mptcp_debug("%s could not multicast packet to group, error [%d]\n", __func__, rc);

        /* no such process */
        if (rc == -ESRCH) {
            mptcp_debug("%s Should be because daemon is not running\n", __func__);
        }
        return;
    }
	mptcp_debug("%s Successfully multicasted\n", __func__);
    return;
}

int recv_genl_context(struct sk_buff *skb, struct genl_info *info)
{
    struct sock* meta_sk;
    struct mptcp_cb *mpcb;
    struct subflow_mod mod;
    struct subflow_mod *modq;
    struct context_priv *pm_priv;

    struct nlattr *nla;
    struct nlmsghdr *netlink_header;
    struct genlmsghdr* gh = info->genlhdr;

    if(!skb) return 0;
    if(!info) return 0;

    mptcp_debug("%s receieved genl message\n", __func__);

    netlink_header = nlmsg_hdr(skb);

    nla = info->attrs[CONTEXT_MPTCP_TOKEN];
    if (nla == 0) {
        mptcp_debug("No MPTCP token available for current host\n");
        return 0;
    } else {
        mod.token = nla_get_u32(nla);
        mptcp_debug("Received nla of type %d and len %d. Token value: %04x\n", nla->nla_type, nla->nla_len, mod.token);
    }

    nla = info->attrs[CONTEXT_SRC_ADDR];
    if (nla == 0) {
        mptcp_debug("Destination port not set\n");
        return 0;
    } else {
        mod.saddr = nla_get_u32(nla);
        mptcp_debug("Received nla of type %d and len %d. SADDR: %d\n", nla->nla_type, nla->nla_len, mod.saddr);
    }

    nla = info->attrs[CONTEXT_DST_ADDR];
    if (nla == 0) {
        mptcp_debug("Destination port not set\n");
        return 0;
    } else {
        mod.daddr = nla_get_u32(nla);
        mptcp_debug("Received nla of type %d and len %d. DADDR: %d\n", nla->nla_type, nla->nla_len, mod.daddr);
    }

	nla = info->attrs[CONTEXT_DST_PORT];
	if (nla == 0) {
		mptcp_debug("Destination port not set\n");
		return 0;
	} else {
		mod.dport = nla_get_u16(nla);
		mptcp_debug("Received nla of type %d and len %d. DPORT: %d\n", nla->nla_type, nla->nla_len, mod.dport);
	}

	nla = info->attrs[CONTEXT_LOC_ID];
	if (nla == 0) {
		mptcp_debug("Destination port not set\n");
		return 0;
	} else {
		mod.locid = nla_get_u32(nla);
		mptcp_debug("Received nla of type %d and len %d. Loc_ID: %d\n", nla->nla_type, nla->nla_len, mod.locid);
	}

    if(gh->cmd == CONTEXT_CMD_CREATE_SUBFLOW) {
        mod.action = SUBFLOW_MOD_ADD;
    } else if(gh->cmd == CONTEXT_CMD_REMOVE_SUBFLOW) {
        mod.action = SUBFLOW_MOD_DEL;
    } else {
        mptcp_debug("Unknown action, don't do anything to the subflow\n");
        return 0;
    }

    meta_sk = mptcp_hash_find(0, mod.token);

    if(!meta_sk){
        mptcp_debug("Could not find meta_sk for token %04x\n", mod.token);
        return -1;
    }

    mpcb = tcp_sk(meta_sk)->mpcb;

    pm_priv = (struct context_priv *)&mpcb->mptcp_pm[0];

    modq = kmemdup(&mod, sizeof(struct subflow_mod), GFP_ATOMIC);
    if (!modq){
        mptcp_debug("Dumping the flow mod failed: %04x\n", mod.token);
        return -1;
    }

    mptcp_debug("%s add flow mod to tail\n", __func__);

    mutex_lock(&mpcb->mpcb_mutex);
    list_add_tail(&modq->list, &pm_priv->flowmods);
    mutex_unlock(&mpcb->mpcb_mutex);

    mptcp_debug("%s create subflows\n", __func__);

    context_create_subflows(meta_sk);

    mptcp_debug("%s success\n", __func__);

    return 0;
}

/**
 * Create all new subflows, by doing calls to mptcp_initX_subsockets
 *
 * This function uses a goto next_subflow, to allow releasing the lock between
 * new subflows and giving other processes a chance to do some work on the
 * socket and potentially finishing the communication.
 **/
static void create_subflow_worker(struct work_struct *work)
{
	struct context_priv *pm_priv = container_of(work,
						     struct context_priv,
						     subflow_work);

	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
    struct subflow_mod *mod = NULL;
    int iter = 0;
    mptcp_debug("%s \n", __func__);

next_flowmod:

    kfree(mod);

    if (iter) {
        mptcp_debug("%s cond_resched()\n", __func__);
        release_sock(meta_sk);
        mutex_unlock(&mpcb->mpcb_mutex);
        cond_resched();
    }

    mutex_lock(&mpcb->mpcb_mutex);
    lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

    iter++;

    if (sock_flag(meta_sk, SOCK_DEAD))
        goto exit;

    if (mpcb->master_sk &&
        !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
        goto exit;

    mod = list_first_entry_or_null(&pm_priv->flowmods,
                     struct subflow_mod, list);
    if (!mod) {
        mptcp_debug("%s no more mods\n", __func__);
        goto exit;
    }

    list_del(&mod->list);

    if(mod->action == SUBFLOW_MOD_ADD){
        struct mptcp_loc4 loc;
        struct mptcp_rem4 rem;
        mptcp_debug("%s add subflow src:(%pI4:0) dst:(%pI4:%d)\n", __func__, &mod->saddr, &mod->daddr, mod->dport);

        loc.addr.s_addr = mod->saddr;
        loc.loc4_id = mod->locid;
        loc.low_prio = 0;

        rem.addr.s_addr = mod->daddr;
        rem.port = mod->dport;
        rem.rem4_id = 0;

        mptcp_init4_subsockets(meta_sk, &loc, &rem);
    } else if(mod->action == SUBFLOW_MOD_DEL){
        struct sock *sk, *tmpsk;

        mptcp_debug("%s delete subflow\n", __func__);
        mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
            if(inet_sk(sk)->inet_saddr == mod->saddr){
                mptcp_reinject_data(sk, 0);
                //announce_remove_addr(tcp_sk(sk)->mptcp->loc_id, meta_sk);
                mptcp_sub_force_close(sk);
            }
        }
    }
    mptcp_debug("%s next flow\n", __func__);

    goto next_flowmod;

exit:
    release_sock(meta_sk);
    mutex_unlock(&mpcb->mpcb_mutex);
    sock_put(meta_sk);
}

static void on_session_establishment(struct sock *meta_sk)
{
    struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
    struct context_priv *pm_priv = (struct context_priv *)mpcb->mptcp_pm;

    if (!work_pending(&pm_priv->register_work)) {
        queue_work(mptcp_wq, &pm_priv->register_work);
    }

    mptcp_debug("%s success\n", __func__);
}

static void context_new_session(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct context_priv *pm_priv = (struct context_priv *)&mpcb->mptcp_pm[0];

	/* Initialize workqueue-struct */
	INIT_WORK(&pm_priv->subflow_work, create_subflow_worker);
    INIT_WORK(&pm_priv->register_work, register_session_with_daemon);
    INIT_WORK(&pm_priv->remove_work, remove_session_from_daemon);
    INIT_LIST_HEAD(&pm_priv->flowmods);
	pm_priv->mpcb = mpcb;
    mptcp_debug("%s success\n", __func__);
}

/* Called upon release_sock, if the socket was owned by the user during
 * a path-management event.
 */
static void context_release_sock(struct sock *meta_sk)
{
    struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
    struct context_priv *pm_priv = (struct context_priv *)mpcb->mptcp_pm;

	mptcp_debug("%s Context Release Sock\n", __func__);

    if (!work_pending(&pm_priv->remove_work)) {
        queue_work(mptcp_wq, &pm_priv->remove_work);
    }

    mptcp_debug("%s success\n", __func__);

}

static void context_create_subflows(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct context_priv *pm_priv = (struct context_priv *)&mpcb->mptcp_pm[0];

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&pm_priv->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &pm_priv->subflow_work);
	}
}

static int context_get_local_id(sa_family_t family, union inet_addr *addr,
				   struct net *net, bool *low_prio)
{
	return 0;
}

static struct mptcp_pm_ops context __read_mostly = {
	.new_session = context_new_session,
    .close_sock = context_release_sock,
	.fully_established = on_session_establishment,
	.get_local_id = context_get_local_id,
	.name = "contextaware",
	.owner = THIS_MODULE,
};

/* General initialization of MPTCP_PM */
static int __init context_register(void)
{
    int rc = 0;

	BUILD_BUG_ON(sizeof(struct context_priv) > MPTCP_PM_SIZE);

	/*register family*/

	rc = genl_register_family_with_ops_groups(&context_genl_family,
			context_genl_ops,
			mptcp_context_multicast_group);

    /*rc = genl_register_family_with_ops(&context_genl_family,
            context_genl_ops);*/
	if (rc != 0) {
		printk(KERN_ERR "%s failed to register genl family: %d\n", __func__, rc);
		goto exit;
	}
	if (mptcp_register_path_manager(&context)){
		printk(KERN_ERR "%s failed to register context-aware path manager\n", __func__);
		goto exit;
	}

	return 0;

exit:
	return -1;
}

static void context_unregister(void)
{
	mptcp_unregister_path_manager(&context);
}

module_init(context_register);
module_exit(context_unregister);

MODULE_AUTHOR("Richard Withnell");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Context Aware MPTCP");
MODULE_VERSION("0.89");
