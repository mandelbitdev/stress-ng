// SPDX-License-Identifier: GPL-2.0-or-later
#include "stress-ng.h"
#include "core-builtin.h"
#include "core-capabilities.h"

static const stress_help_t help[] = {
	{ NULL,	"ovpn N",	"start N workers exercising ovpn tasks events" },
	{ NULL,	"ovpn-ops N",	"stop ovpn workers after N bogo events" },
	{ NULL,	NULL,		NULL }
};

#if defined(HAVE_LIB_NL) && defined(HAVE_LINUX_OVPN_H)

#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ovpn.h>
#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include <sys/random.h>
#include <sys/select.h>
#include <fcntl.h>

#if defined(HAVE_LINUX_CN_PROC_H)
#include <linux/cn_proc.h>
#endif

#if defined(HAVE_LINUX_CONNECTOR_H)
#include <linux/connector.h>
#endif

#if defined(HAVE_LINUX_NETLINK_H)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#endif

#if defined(HAVE_SYS_UIO_H)
#include <sys/uio.h>
#endif

#if defined(HAVE_LINUX_VERSION_H)
#include <linux/version.h>
#endif

/* defines to make checkpatch happy */
#define strscpy strncpy
#define __always_unused __attribute__((__unused__))

/* libnl < 3.5.0 does not set the NLA_F_NESTED on its own, therefore we
 * have to explicitly do it to prevent the kernel from failing upon
 * parsing of the message
 */
#define nla_nest_start(_msg, _type) \
	nla_nest_start(_msg, (_type) | NLA_F_NESTED)

/* libnl < 3.11.0 does not implement nla_get_uint() */
uint64_t ovpn_nla_get_uint(struct nlattr *attr)
{
	if (nla_len(attr) == sizeof(uint32_t))
		return nla_get_u32(attr);
	else
		return nla_get_u64(attr);
}

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

enum ovpn_mode {
	OVPN_MODE_P2P,
	OVPN_MODE_MP,
};

enum {
	IFLA_OVPN_UNSPEC,
	IFLA_OVPN_MODE,
	__IFLA_OVPN_MAX,
};

#define IFLA_OVPN_MAX (__IFLA_OVPN_MAX - 1)

enum ovpn_key_direction {
	KEY_DIR_IN = 0,
	KEY_DIR_OUT,
};

#define KEY_LEN (256 / 8)
#define NONCE_LEN 8

#define PEER_ID_UNDEF 0x00FFFFFF
#define MAX_PEERS 10

struct nl_ctx {
	struct nl_sock *nl_sock;
	struct nl_msg *nl_msg;
	struct nl_cb *nl_cb;

	int ovpn_dco_id;
};

enum ovpn_cmd {
	CMD_INVALID,
	CMD_NEW_IFACE,
	CMD_CONNECT,
	CMD_NEW_PEER,
	CMD_SET_PEER,
	CMD_DEL_PEER,
	CMD_GET_PEER,
	CMD_NEW_KEY,
	CMD_DEL_KEY,
	CMD_GET_KEY,
	CMD_SWAP_KEYS,
};

struct ovpn_ctx {
	enum ovpn_cmd cmd;

	__u8 key_enc[KEY_LEN];
	__u8 key_dec[KEY_LEN];
	__u8 nonce[NONCE_LEN];

	enum ovpn_cipher_alg cipher;

	sa_family_t sa_family;

	unsigned long peer_id;
	unsigned long lport;

	union {
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} remote;

	union {
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} peer_ip;

	bool peer_ip_set;

	unsigned int ifindex;
	char ifname[IFNAMSIZ];
	enum ovpn_mode mode;
	bool mode_set;

	int socket;
	int cli_sockets[MAX_PEERS];

	__u32 keepalive_interval;
	__u32 keepalive_timeout;

	enum ovpn_key_direction key_dir;
	enum ovpn_key_slot key_slot;
	int key_id;

	const char *peers_file;
};

struct ovpn_link_req {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[256];
};

/* Helper function used to easily add attributes to a rtnl message */
static int ovpn_addattr(struct nlmsghdr *n, int maxlen, int type,
			const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if ((int)(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len)) > maxlen)	{
		fprintf(stderr, "%s: rtnl: message exceeded bound of %d\n",
			__func__, maxlen);
		return -EMSGSIZE;
	}

	rta = nlmsg_tail(n);
	rta->rta_type = type;
	rta->rta_len = len;

	if (!data)
		memset(RTA_DATA(rta), 0, alen);
	else
		memcpy(RTA_DATA(rta), data, alen);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

static struct rtattr *ovpn_nest_start(struct nlmsghdr *msg, size_t max_size,
				      int attr)
{
	struct rtattr *nest = nlmsg_tail(msg);

	if (ovpn_addattr(msg, max_size, attr, NULL, 0) < 0)
		return NULL;

	return nest;
}

static void ovpn_nest_end(struct nlmsghdr *msg, struct rtattr *nest)
{
	nest->rta_len = (uint8_t *)nlmsg_tail(msg) - (uint8_t *)nest;
}

#define RT_SNDBUF_SIZE (1024 * 2)
#define RT_RCVBUF_SIZE (1024 * 4)

typedef int (*ovpn_parse_reply_cb)(struct nlmsghdr *msg, void *arg);

/* Open RTNL socket */
static int ovpn_rt_socket(void)
{
	int sndbuf = RT_SNDBUF_SIZE, rcvbuf = RT_RCVBUF_SIZE, fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open netlink socket\n", __func__);
		return fd;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf,
		       sizeof(sndbuf)) < 0) {
		fprintf(stderr, "%s: SO_SNDBUF\n", __func__);
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
		       sizeof(rcvbuf)) < 0) {
		fprintf(stderr, "%s: SO_RCVBUF\n", __func__);
		close(fd);
		return -1;
	}

	return fd;
}

/* Bind socket to Netlink subsystem */
static int ovpn_rt_bind(int fd, uint32_t groups)
{
	struct sockaddr_nl local = { 0 };
	socklen_t addr_len;

	local.nl_family = AF_NETLINK;
	local.nl_groups = groups;

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		fprintf(stderr, "%s: cannot bind netlink socket: %d\n",
			__func__, errno);
		return -errno;
	}

	addr_len = sizeof(local);
	if (getsockname(fd, (struct sockaddr *)&local, &addr_len) < 0) {
		fprintf(stderr, "%s: cannot getsockname: %d\n", __func__,
			errno);
		return -errno;
	}

	if (addr_len != sizeof(local)) {
		fprintf(stderr, "%s: wrong address length %d\n", __func__,
			addr_len);
		return -EINVAL;
	}

	if (local.nl_family != AF_NETLINK) {
		fprintf(stderr, "%s: wrong address family %d\n", __func__,
			local.nl_family);
		return -EINVAL;
	}

	return 0;
}

/* Send Netlink message and run callback on reply (if specified) */
static int ovpn_rt_send(struct nlmsghdr *payload, pid_t peer,
	unsigned int groups, ovpn_parse_reply_cb cb,
	void *arg_cb)
{
	int len, rem_len, fd, ret, rcv_len;
	struct sockaddr_nl nladdr = { 0 };
	struct nlmsgerr *err;
	struct nlmsghdr *h;
	char buf[1024 * 16];
	struct iovec iov = {
		.iov_base = payload,
		.iov_len = payload->nlmsg_len,
	};
	struct msghdr nlmsg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

	payload->nlmsg_seq = time(NULL);

	/* no need to send reply */
	if (!cb)
		payload->nlmsg_flags |= NLM_F_ACK;

	fd = ovpn_rt_socket();
	if (fd < 0) {
		fprintf(stderr, "%s: can't open rtnl socket\n", __func__);
		return -errno;
	}

	ret = ovpn_rt_bind(fd, 0);
	if (ret < 0) {
		fprintf(stderr, "%s: can't bind rtnl socket\n", __func__);
		ret = -errno;
		goto out;
	}

	ret = sendmsg(fd, &nlmsg, 0);
	if (ret < 0) {
		fprintf(stderr, "%s: rtnl: error on sendmsg()\n", __func__);
		ret = -errno;
		goto out;
	}

	/* prepare buffer to store RTNL replies */
	memset(buf, 0, sizeof(buf));
	iov.iov_base = buf;

	while (1) {
		/*
		 * iov_len is modified by recvmsg(), therefore has to be initialized before
		 * using it again
		 */
		iov.iov_len = sizeof(buf);
		rcv_len = recvmsg(fd, &nlmsg, 0);
		if (rcv_len < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				fprintf(stderr, "%s: interrupted call\n",
					__func__);
				continue;
			}
			fprintf(stderr, "%s: rtnl: error on recvmsg()\n",
				__func__);
			ret = -errno;
			goto out;
		}

		if (rcv_len == 0) {
			fprintf(stderr,
				"%s: rtnl: socket reached unexpected EOF\n",
				__func__);
			ret = -EIO;
			goto out;
		}

		if (nlmsg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr,
				"%s: sender address length: %u (expected %zu)\n",
				__func__, nlmsg.msg_namelen, sizeof(nladdr));
			ret = -EIO;
			goto out;
		}

		h = (struct nlmsghdr *)buf;
		while (rcv_len >= (int)sizeof(*h)) {
			len = h->nlmsg_len;
			rem_len = len - sizeof(*h);

			if (rem_len < 0 || len > rcv_len) {
				if (nlmsg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "%s: truncated message\n",
						__func__);
					ret = -EIO;
					goto out;
				}
				fprintf(stderr, "%s: malformed message: len=%d\n",
					__func__, len);
				ret = -EIO;
				goto out;
			}

			if (h->nlmsg_type == NLMSG_DONE) {
				ret = 0;
				goto out;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				err = (struct nlmsgerr *)NLMSG_DATA(h);
				if (rem_len < (int)sizeof(struct nlmsgerr)) {
					fprintf(stderr, "%s: ERROR truncated\n",
						__func__);
					ret = -EIO;
					goto out;
				}

				if (err->error) {
					fprintf(stderr, "%s: (%d) %s\n",
						__func__, err->error,
						strerror(-err->error));
					ret = err->error;
					goto out;
				}

				ret = 0;
				if (cb) {
					int r = cb(h, arg_cb);

					if (r <= 0)
						ret = r;
				}
				goto out;
			}

			if (cb) {
				int r = cb(h, arg_cb);

				if (r <= 0) {
					ret = r;
					goto out;
				}
			} else {
				fprintf(stderr, "%s: RTNL: unexpected reply\n",
					__func__);
			}

			rcv_len -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((uint8_t *)h +
						NLMSG_ALIGN(len));
		}

		if (nlmsg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "%s: message truncated\n", __func__);
			continue;
		}

		if (rcv_len) {
			fprintf(stderr, "%s: rtnl: %d not parsed bytes\n",
				__func__, rcv_len);
			ret = -1;
			goto out;
		}
	}
out:
	close(fd);

	return ret;
}

static int ovpn_socket(struct ovpn_ctx *ctx, sa_family_t family, int proto)
{
	struct sockaddr_storage local_sock = { 0 };
	struct sockaddr_in6 *in6;
	struct sockaddr_in *in;
	int ret, s, sock_type;
	size_t sock_len;

	if (proto == IPPROTO_UDP)
		sock_type = SOCK_DGRAM;
	else if (proto == IPPROTO_TCP)
		sock_type = SOCK_STREAM;
	else
		return -EINVAL;

	s = socket(family, sock_type, 0);
	if (s < 0) {
		perror("cannot create socket");
		return -1;
	}

	switch (family) {
	case AF_INET:
		in = (struct sockaddr_in *)&local_sock;
		in->sin_family = family;
		in->sin_port = htons(ctx->lport);
		in->sin_addr.s_addr = htonl(INADDR_ANY);
		sock_len = sizeof(*in);
		break;
	case AF_INET6:
		in6 = (struct sockaddr_in6 *)&local_sock;
		in6->sin6_family = family;
		in6->sin6_port = htons(ctx->lport);
		in6->sin6_addr = in6addr_any;
		sock_len = sizeof(*in6);
		break;
	default:
		return -1;
	}

	int opt = 1;

	ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret < 0) {
		perror("setsockopt for SO_REUSEADDR");
		return ret;
	}

	ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	if (ret < 0) {
		perror("setsockopt for SO_REUSEPORT");
		return ret;
	}

	if (family == AF_INET6) {
		opt = 0;
		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
			       sizeof(opt))) {
			perror("failed to set IPV6_V6ONLY");
			return -1;
		}
	}

	ret = bind(s, (struct sockaddr *)&local_sock, sock_len);
	if (ret < 0) {
		perror("cannot bind socket");
		goto err_socket;
	}

	ctx->socket = s;
	ctx->sa_family = family;
	return 0;

err_socket:
	close(s);
	return -1;
}

static int ovpn_new_iface(struct ovpn_ctx *ovpn)
{
	struct rtattr *linkinfo, *data;
	struct ovpn_link_req req = { 0 };
	int ret = -1;

	fprintf(stdout, "Creating interface %s with mode %u\n", ovpn->ifname,
		ovpn->mode);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;

	if (ovpn_addattr(&req.n, sizeof(req), IFLA_IFNAME, ovpn->ifname,
			 strlen(ovpn->ifname) + 1) < 0)
		goto err;

	linkinfo = ovpn_nest_start(&req.n, sizeof(req), IFLA_LINKINFO);
	if (!linkinfo)
		goto err;

	if (ovpn_addattr(&req.n, sizeof(req), IFLA_INFO_KIND, OVPN_FAMILY_NAME,
			 strlen(OVPN_FAMILY_NAME) + 1) < 0)
		goto err;

	if (ovpn->mode_set) {
		data = ovpn_nest_start(&req.n, sizeof(req), IFLA_INFO_DATA);
		if (!data)
			goto err;

		if (ovpn_addattr(&req.n, sizeof(req), IFLA_OVPN_MODE,
				 &ovpn->mode, sizeof(uint8_t)) < 0)
			goto err;

		ovpn_nest_end(&req.n, data);
	}

	ovpn_nest_end(&req.n, linkinfo);

	req.i.ifi_family = AF_PACKET;

	ret = ovpn_rt_send(&req.n, 0, 0, NULL, NULL);
err:
	return ret;
}

static struct nl_ctx *nl_ctx_alloc_flags(struct ovpn_ctx *ovpn, int cmd,
	int flags)
{
	struct nl_ctx *ctx;
	int err, ret;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->nl_sock = nl_socket_alloc();
	if (!ctx->nl_sock) {
		fprintf(stderr, "cannot allocate netlink socket\n");
		goto err_free;
	}

	nl_socket_set_buffer_size(ctx->nl_sock, 8192, 8192);

	ret = genl_connect(ctx->nl_sock);
	if (ret) {
		fprintf(stderr, "cannot connect to generic netlink: %s\n",
			nl_geterror(ret));
		goto err_sock;
	}

	/* enable Extended ACK for detailed error reporting */
	err = 1;
	setsockopt(nl_socket_get_fd(ctx->nl_sock), SOL_NETLINK, NETLINK_EXT_ACK,
		   &err, sizeof(err));

	ctx->ovpn_dco_id = genl_ctrl_resolve(ctx->nl_sock, OVPN_FAMILY_NAME);
	if (ctx->ovpn_dco_id < 0) {
		fprintf(stderr, "cannot find ovpn_dco netlink component: %d\n",
			ctx->ovpn_dco_id);
		goto err_free;
	}

	ctx->nl_msg = nlmsg_alloc();
	if (!ctx->nl_msg) {
		fprintf(stderr, "cannot allocate netlink message\n");
		goto err_sock;
	}

	ctx->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!ctx->nl_cb) {
		fprintf(stderr, "failed to allocate netlink callback\n");
		goto err_msg;
	}

	nl_socket_set_cb(ctx->nl_sock, ctx->nl_cb);

	genlmsg_put(ctx->nl_msg, 0, 0, ctx->ovpn_dco_id, 0, flags, cmd, 0);

	if (ovpn->ifindex > 0)
		NLA_PUT_U32(ctx->nl_msg, OVPN_A_IFINDEX, ovpn->ifindex);

	return ctx;
nla_put_failure:
err_msg:
	nlmsg_free(ctx->nl_msg);
err_sock:
	nl_socket_free(ctx->nl_sock);
err_free:
	free(ctx);
	return NULL;
}

static struct nl_ctx *nl_ctx_alloc(struct ovpn_ctx *ovpn, int cmd)
{
	return nl_ctx_alloc_flags(ovpn, cmd, 0);
}

static int ovpn_nl_cb_finish(struct nl_msg (*msg)__always_unused, void *arg)
{
	int *status = arg;

	*status = 0;
	return NL_SKIP;
}

static int ovpn_nl_cb_ack(struct nl_msg (*msg)__always_unused,
			  void *arg)
{
	int *status = arg;

	*status = 0;
	return NL_STOP;
}

static int ovpn_nl_recvmsgs(struct nl_ctx *ctx)
{
	int ret;

	ret = nl_recvmsgs(ctx->nl_sock, ctx->nl_cb);

	switch (ret) {
	case -NLE_INTR:
		fprintf(stderr,
			"netlink received interrupt due to signal - ignoring\n");
		break;
	case -NLE_NOMEM:
		fprintf(stderr, "netlink out of memory error\n");
		break;
	case -NLE_AGAIN:
		fprintf(stderr,
			"netlink reports blocking read - aborting wait\n");
		break;
	default:
		if (ret)
			fprintf(stderr, "netlink reports error (%d): %s\n",
				ret, nl_geterror(-ret));
		break;
	}

	return ret;
}

static int ovpn_nl_cb_error(struct sockaddr_nl (*nla)__always_unused,
			    struct nlmsgerr *err, void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
	struct nlattr *tb_msg[NLMSGERR_ATTR_MAX + 1];
	int len = nlh->nlmsg_len;
	struct nlattr *attrs;
	int *ret = arg;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

	*ret = err->error;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	if (len <= ack_len)
		return NL_STOP;

	attrs = (void *)((uint8_t *)nlh + ack_len);
	len -= ack_len;

	nla_parse(tb_msg, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb_msg[NLMSGERR_ATTR_MSG]) {
		len = strnlen((char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]),
			      nla_len(tb_msg[NLMSGERR_ATTR_MSG]));
		fprintf(stderr, "kernel error: %*s\n", len,
			(char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]));
	}

#ifdef NLMSGERR_ATTR_MISS_NEST
	if (tb_msg[NLMSGERR_ATTR_MISS_NEST]) {
		fprintf(stderr, "missing required nesting type %u\n",
			nla_get_u32(tb_msg[NLMSGERR_ATTR_MISS_NEST]));
	}
#endif

#ifdef NLMSGERR_ATTR_MISS_TYPE
	if (tb_msg[NLMSGERR_ATTR_MISS_TYPE]) {
		fprintf(stderr, "missing required attribute type %u\n",
			nla_get_u32(tb_msg[NLMSGERR_ATTR_MISS_TYPE]));
	}
#endif

	return NL_STOP;
}

static int ovpn_nl_msg_send(struct nl_ctx *ctx, ovpn_nl_cb cb)
{
	int status = 1;

	nl_cb_err(ctx->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &status);
	nl_cb_set(ctx->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish, &status);
	nl_cb_set(ctx->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_ack, &status);

	if (cb)
		nl_cb_set(ctx->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, ctx);

	nl_send_auto_complete(ctx->nl_sock, ctx->nl_msg);

	while (status == 1)
		ovpn_nl_recvmsgs(ctx);

	if (status < 0)
		fprintf(stderr, "failed to send netlink message: %s (%d)\n",
			strerror(-status), status);

	return status;
}

static void nl_ctx_free(struct nl_ctx *ctx)
{
	if (!ctx)
		return;

	nl_socket_free(ctx->nl_sock);
	nlmsg_free(ctx->nl_msg);
	nl_cb_put(ctx->nl_cb);
	free(ctx);
}

static int ovpn_new_peer(struct ovpn_ctx *ovpn, bool is_tcp)
{
	struct nlattr *attr;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_PEER_NEW);
	if (!ctx)
		return -ENOMEM;

	attr = nla_nest_start(ctx->nl_msg, OVPN_A_PEER);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_ID, ovpn->peer_id);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_SOCKET, ovpn->socket);

	if (!is_tcp) {
		switch (ovpn->remote.in4.sin_family) {
		case AF_INET:
			NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_REMOTE_IPV4,
				    ovpn->remote.in4.sin_addr.s_addr);
			NLA_PUT_U16(ctx->nl_msg, OVPN_A_PEER_REMOTE_PORT,
				    ovpn->remote.in4.sin_port);
			break;
		case AF_INET6:
			NLA_PUT(ctx->nl_msg, OVPN_A_PEER_REMOTE_IPV6,
				sizeof(ovpn->remote.in6.sin6_addr),
				&ovpn->remote.in6.sin6_addr);
			NLA_PUT_U32(ctx->nl_msg,
				    OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID,
				    ovpn->remote.in6.sin6_scope_id);
			NLA_PUT_U16(ctx->nl_msg, OVPN_A_PEER_REMOTE_PORT,
				    ovpn->remote.in6.sin6_port);
			break;
		default:
			fprintf(stderr,
				"Invalid family for remote socket address\n");
			goto nla_put_failure;
		}
	}

	if (ovpn->peer_ip_set) {
		switch (ovpn->peer_ip.in4.sin_family) {
		case AF_INET:
			NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_VPN_IPV4,
				    ovpn->peer_ip.in4.sin_addr.s_addr);
			break;
		case AF_INET6:
			NLA_PUT(ctx->nl_msg, OVPN_A_PEER_VPN_IPV6,
				sizeof(struct in6_addr),
				&ovpn->peer_ip.in6.sin6_addr);
			break;
		default:
			fprintf(stderr, "Invalid family for peer address\n");
			goto nla_put_failure;
		}
	}

	nla_nest_end(ctx->nl_msg, attr);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_parse_remote(struct ovpn_ctx *ovpn, const char *host,
	const char *service, const char *vpnip)
{
	int ret;
	struct addrinfo *result;
	struct addrinfo hints = {
		.ai_family = ovpn->sa_family,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};

	if (host) {
		ret = getaddrinfo(host, service, &hints, &result);
		if (ret) {
			fprintf(stderr, "getaddrinfo on remote error: %s\n",
				gai_strerror(ret));
			return -1;
		}

		if (!(result->ai_family == AF_INET &&
		      result->ai_addrlen == sizeof(struct sockaddr_in)) &&
		    !(result->ai_family == AF_INET6 &&
		      result->ai_addrlen == sizeof(struct sockaddr_in6))) {
			ret = -EINVAL;
			goto out;
		}

		memcpy(&ovpn->remote, result->ai_addr, result->ai_addrlen);
	}

	if (vpnip) {
		ret = getaddrinfo(vpnip, NULL, &hints, &result);
		if (ret) {
			fprintf(stderr, "getaddrinfo on vpnip error: %s\n",
				gai_strerror(ret));
			return -1;
		}

		if (!(result->ai_family == AF_INET &&
		      result->ai_addrlen == sizeof(struct sockaddr_in)) &&
		    !(result->ai_family == AF_INET6 &&
		      result->ai_addrlen == sizeof(struct sockaddr_in6))) {
			ret = -EINVAL;
			goto out;
		}

		memcpy(&ovpn->peer_ip, result->ai_addr, result->ai_addrlen);
		ovpn->sa_family = result->ai_family;

		ovpn->peer_ip_set = true;
	}

	ret = 0;
out:
	freeaddrinfo(result);
	return ret;
}

static int ovpn_parse_new_peer(struct ovpn_ctx *ovpn, int peer_id,
	const char *raddr, const char *rport,
	const char *vpnip)
{
	ovpn->peer_id = peer_id;
	if (ovpn->peer_id > PEER_ID_UNDEF) {
		fprintf(stderr, "peer ID value out of range\n");
		return -1;
	}

	return ovpn_parse_remote(ovpn, raddr, rport, vpnip);
}


static int ovpn_connect(struct ovpn_ctx *ovpn)
{
	socklen_t socklen;
	int s, ret, flags;
	fd_set wfds;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	s = socket(ovpn->remote.in4.sin_family, SOCK_STREAM, 0);
	if (s < 0) {
		perror("cannot create socket");
		return -1;
	}

	switch (ovpn->remote.in4.sin_family) {
	case AF_INET:
		socklen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		socklen = sizeof(struct sockaddr_in6);
		break;
	default:
		ret = -EOPNOTSUPP;
		goto err;
	}

	flags = fcntl(s, F_GETFL, 0);
	if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("fcntl");
		ret = -1;
		goto err;
	}

	ret = connect(s, (struct sockaddr *)&ovpn->remote, socklen);
	if (ret < 0 && errno != EINPROGRESS) {
		perror("connect");
		goto err;
	}

	FD_ZERO(&wfds);
	FD_SET(s, &wfds);
	ret = select(s + 1, NULL, &wfds, NULL, &tv);
	if (ret <= 0) {
		ret = (ret == 0) ? -ETIMEDOUT : -errno;
		goto err;
	}

	/* restore blocking mode */
	(void)fcntl(s, F_SETFL, flags);

	ovpn->socket = s;

	return 0;
err:
	close(s);
	return ret;
}

static int ovpn_new_key(struct ovpn_ctx *ovpn)
{
	struct nlattr *keyconf, *key_dir;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_KEY_NEW);
	if (!ctx)
		return -ENOMEM;

	keyconf = nla_nest_start(ctx->nl_msg, OVPN_A_KEYCONF);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_PEER_ID, ovpn->peer_id);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_SLOT, ovpn->key_slot);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_KEY_ID, ovpn->key_id);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_CIPHER_ALG, ovpn->cipher);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_A_KEYCONF_ENCRYPT_DIR);
	NLA_PUT(ctx->nl_msg, OVPN_A_KEYDIR_CIPHER_KEY, KEY_LEN, ovpn->key_enc);
	NLA_PUT(ctx->nl_msg, OVPN_A_KEYDIR_NONCE_TAIL, NONCE_LEN, ovpn->nonce);
	nla_nest_end(ctx->nl_msg, key_dir);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_A_KEYCONF_DECRYPT_DIR);
	NLA_PUT(ctx->nl_msg, OVPN_A_KEYDIR_CIPHER_KEY, KEY_LEN, ovpn->key_dec);
	NLA_PUT(ctx->nl_msg, OVPN_A_KEYDIR_NONCE_TAIL, NONCE_LEN, ovpn->nonce);
	nla_nest_end(ctx->nl_msg, key_dir);

	nla_nest_end(ctx->nl_msg, keyconf);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_send_tcp_data(int socket)
{
	uint16_t len = htons(1000);
	uint8_t buf[1002];
	int ret;

	memcpy(buf, &len, sizeof(len));
	memset(buf + sizeof(len), 0x86, sizeof(buf) - sizeof(len));

	ret = send(socket, buf, sizeof(buf), MSG_NOSIGNAL);

	fprintf(stdout, "Sent %u bytes over TCP socket\n", ret);

	return ret > 0 ? 0 : ret;
}

static int ovpn_udp_socket(struct ovpn_ctx *ctx, sa_family_t family)
{
	return ovpn_socket(ctx, family, IPPROTO_UDP);
}

static int ovpn_set_peer(struct ovpn_ctx *ovpn)
{
	struct nlattr *attr;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_PEER_SET);
	if (!ctx)
		return -ENOMEM;

	attr = nla_nest_start(ctx->nl_msg, OVPN_A_PEER);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_ID, ovpn->peer_id);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_KEEPALIVE_INTERVAL,
		    ovpn->keepalive_interval);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_KEEPALIVE_TIMEOUT,
		    ovpn->keepalive_timeout);
	nla_nest_end(ctx->nl_msg, attr);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_del_peer(struct ovpn_ctx *ovpn)
{
	struct nlattr *attr;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_PEER_DEL);
	if (!ctx)
		return -ENOMEM;

	attr = nla_nest_start(ctx->nl_msg, OVPN_A_PEER);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_ID, ovpn->peer_id);
	nla_nest_end(ctx->nl_msg, attr);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_swap_keys(struct ovpn_ctx *ovpn)
{
	struct nl_ctx *ctx;
	struct nlattr *kc;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_KEY_SWAP);
	if (!ctx)
		return -ENOMEM;

	kc = nla_nest_start(ctx->nl_msg, OVPN_A_KEYCONF);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_PEER_ID, ovpn->peer_id);
	nla_nest_end(ctx->nl_msg, kc);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_del_key(struct ovpn_ctx *ovpn)
{
	struct nlattr *keyconf;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_KEY_DEL);
	if (!ctx)
		return -ENOMEM;

	keyconf = nla_nest_start(ctx->nl_msg, OVPN_A_KEYCONF);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_PEER_ID, ovpn->peer_id);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_SLOT, ovpn->key_slot);
	nla_nest_end(ctx->nl_msg, keyconf);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_handle_peer(struct nl_msg *msg, void (*arg)__always_unused)
{
	struct nlattr *pattrs[OVPN_A_PEER_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[OVPN_A_MAX + 1];
	__u16 rport = 0, lport = 0;

	nla_parse(attrs, OVPN_A_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!attrs[OVPN_A_PEER]) {
		fprintf(stderr, "no packet content in netlink message\n");
		return NL_SKIP;
	}

	nla_parse(pattrs, OVPN_A_PEER_MAX, nla_data(attrs[OVPN_A_PEER]),
		  nla_len(attrs[OVPN_A_PEER]), NULL);

	if (pattrs[OVPN_A_PEER_ID])
		fprintf(stderr, "* Peer %u\n",
			nla_get_u32(pattrs[OVPN_A_PEER_ID]));

	if (pattrs[OVPN_A_PEER_SOCKET_NETNSID])
		fprintf(stderr, "\tsocket NetNS ID: %d\n",
			nla_get_s32(pattrs[OVPN_A_PEER_SOCKET_NETNSID]));

	if (pattrs[OVPN_A_PEER_VPN_IPV4]) {
		char buf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, nla_data(pattrs[OVPN_A_PEER_VPN_IPV4]),
			  buf, sizeof(buf));
		fprintf(stderr, "\tVPN IPv4: %s\n", buf);
	}

	if (pattrs[OVPN_A_PEER_VPN_IPV6]) {
		char buf[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, nla_data(pattrs[OVPN_A_PEER_VPN_IPV6]),
			  buf, sizeof(buf));
		fprintf(stderr, "\tVPN IPv6: %s\n", buf);
	}

	if (pattrs[OVPN_A_PEER_LOCAL_PORT])
		lport = ntohs(nla_get_u16(pattrs[OVPN_A_PEER_LOCAL_PORT]));

	if (pattrs[OVPN_A_PEER_REMOTE_PORT])
		rport = ntohs(nla_get_u16(pattrs[OVPN_A_PEER_REMOTE_PORT]));

	if (pattrs[OVPN_A_PEER_REMOTE_IPV6]) {
		void *ip = pattrs[OVPN_A_PEER_REMOTE_IPV6];
		char buf[INET6_ADDRSTRLEN];
		int scope_id = -1;

		if (pattrs[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID]) {
			void *p = pattrs[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID];

			scope_id = nla_get_u32(p);
		}

		inet_ntop(AF_INET6, nla_data(ip), buf, sizeof(buf));
		fprintf(stderr, "\tRemote: %s:%hu (scope-id: %u)\n", buf, rport,
			scope_id);

		if (pattrs[OVPN_A_PEER_LOCAL_IPV6]) {
			void *ip = pattrs[OVPN_A_PEER_LOCAL_IPV6];

			inet_ntop(AF_INET6, nla_data(ip), buf, sizeof(buf));
			fprintf(stderr, "\tLocal: %s:%hu\n", buf, lport);
		}
	}

	if (pattrs[OVPN_A_PEER_REMOTE_IPV4]) {
		void *ip = pattrs[OVPN_A_PEER_REMOTE_IPV4];
		char buf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, nla_data(ip), buf, sizeof(buf));
		fprintf(stderr, "\tRemote: %s:%hu\n", buf, rport);

		if (pattrs[OVPN_A_PEER_LOCAL_IPV4]) {
			void *p = pattrs[OVPN_A_PEER_LOCAL_IPV4];

			inet_ntop(AF_INET, nla_data(p), buf, sizeof(buf));
			fprintf(stderr, "\tLocal: %s:%hu\n", buf, lport);
		}
	}

	if (pattrs[OVPN_A_PEER_KEEPALIVE_INTERVAL]) {
		void *p = pattrs[OVPN_A_PEER_KEEPALIVE_INTERVAL];

		fprintf(stderr, "\tKeepalive interval: %u sec\n",
			nla_get_u32(p));
	}

	if (pattrs[OVPN_A_PEER_KEEPALIVE_TIMEOUT])
		fprintf(stderr, "\tKeepalive timeout: %u sec\n",
			nla_get_u32(pattrs[OVPN_A_PEER_KEEPALIVE_TIMEOUT]));

	if (pattrs[OVPN_A_PEER_VPN_RX_BYTES])
		fprintf(stderr, "\tVPN RX bytes: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_VPN_RX_BYTES]));

	if (pattrs[OVPN_A_PEER_VPN_TX_BYTES])
		fprintf(stderr, "\tVPN TX bytes: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_VPN_TX_BYTES]));

	if (pattrs[OVPN_A_PEER_VPN_RX_PACKETS])
		fprintf(stderr, "\tVPN RX packets: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_VPN_RX_PACKETS]));

	if (pattrs[OVPN_A_PEER_VPN_TX_PACKETS])
		fprintf(stderr, "\tVPN TX packets: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_VPN_TX_PACKETS]));

	if (pattrs[OVPN_A_PEER_LINK_RX_BYTES])
		fprintf(stderr, "\tLINK RX bytes: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_LINK_RX_BYTES]));

	if (pattrs[OVPN_A_PEER_LINK_TX_BYTES])
		fprintf(stderr, "\tLINK TX bytes: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_LINK_TX_BYTES]));

	if (pattrs[OVPN_A_PEER_LINK_RX_PACKETS])
		fprintf(stderr, "\tLINK RX packets: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_LINK_RX_PACKETS]));

	if (pattrs[OVPN_A_PEER_LINK_TX_PACKETS])
		fprintf(stderr, "\tLINK TX packets: %" PRIu64 "\n",
			ovpn_nla_get_uint(pattrs[OVPN_A_PEER_LINK_TX_PACKETS]));

	return NL_SKIP;
}

static int ovpn_get_peer(struct ovpn_ctx *ovpn)
{
	int flags = 0, ret = -1;
	struct nlattr *attr;
	struct nl_ctx *ctx;

	if (ovpn->peer_id == PEER_ID_UNDEF)
		flags = NLM_F_DUMP;

	ctx = nl_ctx_alloc_flags(ovpn, OVPN_CMD_PEER_GET, flags);
	if (!ctx)
		return -ENOMEM;

	if (ovpn->peer_id != PEER_ID_UNDEF) {
		attr = nla_nest_start(ctx->nl_msg, OVPN_A_PEER);
		NLA_PUT_U32(ctx->nl_msg, OVPN_A_PEER_ID, ovpn->peer_id);
		nla_nest_end(ctx->nl_msg, attr);
	}

	ret = ovpn_nl_msg_send(ctx, ovpn_handle_peer);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_handle_key(struct nl_msg *msg, void (*arg)__always_unused)
{
	struct nlattr *kattrs[OVPN_A_KEYCONF_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[OVPN_A_MAX + 1];

	nla_parse(attrs, OVPN_A_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!attrs[OVPN_A_KEYCONF]) {
		fprintf(stderr, "no packet content in netlink message\n");
		return NL_SKIP;
	}

	nla_parse(kattrs, OVPN_A_KEYCONF_MAX, nla_data(attrs[OVPN_A_KEYCONF]),
		  nla_len(attrs[OVPN_A_KEYCONF]), NULL);

	if (kattrs[OVPN_A_KEYCONF_PEER_ID])
		fprintf(stderr, "* Peer %u\n",
			nla_get_u32(kattrs[OVPN_A_KEYCONF_PEER_ID]));
	if (kattrs[OVPN_A_KEYCONF_SLOT]) {
		fprintf(stderr, "\t- Slot: ");
		switch (nla_get_u32(kattrs[OVPN_A_KEYCONF_SLOT])) {
		case OVPN_KEY_SLOT_PRIMARY:
			fprintf(stderr, "primary\n");
			break;
		case OVPN_KEY_SLOT_SECONDARY:
			fprintf(stderr, "secondary\n");
			break;
		default:
			fprintf(stderr, "invalid (%u)\n",
				nla_get_u32(kattrs[OVPN_A_KEYCONF_SLOT]));
			break;
		}
	}
	if (kattrs[OVPN_A_KEYCONF_KEY_ID])
		fprintf(stderr, "\t- Key ID: %u\n",
			nla_get_u32(kattrs[OVPN_A_KEYCONF_KEY_ID]));
	if (kattrs[OVPN_A_KEYCONF_CIPHER_ALG]) {
		fprintf(stderr, "\t- Cipher: ");
		switch (nla_get_u32(kattrs[OVPN_A_KEYCONF_CIPHER_ALG])) {
		case OVPN_CIPHER_ALG_NONE:
			fprintf(stderr, "none\n");
			break;
		case OVPN_CIPHER_ALG_AES_GCM:
			fprintf(stderr, "aes-gcm\n");
			break;
		case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
			fprintf(stderr, "chacha20poly1305\n");
			break;
		default:
			fprintf(stderr, "invalid (%u)\n",
				nla_get_u32(kattrs[OVPN_A_KEYCONF_CIPHER_ALG]));
			break;
		}
	}

	return NL_SKIP;
}

static int ovpn_get_key(struct ovpn_ctx *ovpn)
{
	struct nlattr *keyconf;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_KEY_GET);
	if (!ctx)
		return -ENOMEM;

	keyconf = nla_nest_start(ctx->nl_msg, OVPN_A_KEYCONF);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_PEER_ID, ovpn->peer_id);
	NLA_PUT_U32(ctx->nl_msg, OVPN_A_KEYCONF_SLOT, ovpn->key_slot);
	nla_nest_end(ctx->nl_msg, keyconf);

	ret = ovpn_nl_msg_send(ctx, ovpn_handle_key);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_run_cmd(struct ovpn_ctx *ovpn)
{
	int ret = 0;

	switch (ovpn->cmd) {
	case CMD_NEW_IFACE:
		ret = ovpn_new_iface(ovpn);
		break;
	case CMD_CONNECT:
		ret = ovpn_connect(ovpn);
		if (ret < 0) {
			fprintf(stderr, "cannot connect TCP socket\n");
			return ret;
		}

		ret = ovpn_new_peer(ovpn, true);
		if (ret < 0) {
			fprintf(stderr, "cannot add peer to VPN\n");
			close(ovpn->socket);
			return ret;
		}

		if (ovpn->cipher != OVPN_CIPHER_ALG_NONE) {
			ret = ovpn_new_key(ovpn);
			if (ret < 0) {
				fprintf(stderr, "cannot set key\n");
				return ret;
			}
		}

		ret = ovpn_send_tcp_data(ovpn->socket);
		break;
	case CMD_NEW_PEER:
		ret = ovpn_udp_socket(ovpn, AF_INET6);
		if (ret < 0)
			return ret;

		ret = ovpn_new_peer(ovpn, false);
		break;
	case CMD_SET_PEER:
		ret = ovpn_set_peer(ovpn);
		break;
	case CMD_DEL_PEER:
		ret = ovpn_del_peer(ovpn);
		break;
	case CMD_GET_PEER:
		if (ovpn->peer_id == PEER_ID_UNDEF)
			fprintf(stderr, "List of peers connected to: %s\n",
				ovpn->ifname);

		ret = ovpn_get_peer(ovpn);
		break;
	case CMD_NEW_KEY:
		ret = ovpn_new_key(ovpn);
		break;
	case CMD_DEL_KEY:
		ret = ovpn_del_key(ovpn);
		break;
	case CMD_GET_KEY:
		ret = ovpn_get_key(ovpn);
		break;
	case CMD_SWAP_KEYS:
		ret = ovpn_swap_keys(ovpn);
		break;
	case CMD_INVALID:
		break;
	}

	return ret;
}


static int stress_ovpn_supported(const char *name)
{
	if (!stress_capabilities_check(SHIM_CAP_NET_ADMIN)) {
		pr_inf_skip("%s stressor will be skipped, need to be running with CAP_NET_ADMIN rights for this stressor\n",
			name);
		return -1;
	}
	return 0;
}


static void ovpn_ctx_reset(struct ovpn_ctx *ovpn)
{
	memset(ovpn, 0, sizeof(*ovpn));

	ovpn->socket = -1;

	strscpy(ovpn->ifname, "tun0", IFNAMSIZ);
	ovpn->ifindex = if_nametoindex(ovpn->ifname);

	ovpn->sa_family = AF_INET;
	ovpn->cipher = OVPN_CIPHER_ALG_NONE;
}

static int build_new_iface(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);

	ovpn->cmd = CMD_NEW_IFACE;
	ovpn->mode = (stress_mwc32() & 1) ? OVPN_MODE_P2P : OVPN_MODE_MP;
	ovpn->mode_set = true;

	return 0;
}


static int ovpn_generate_key(struct ovpn_ctx *ctx)
{
	if (getrandom(ctx->key_enc, KEY_LEN, 0) != KEY_LEN) {
		perror("getrandom(key_enc)");
		return -1;
	}

	if (getrandom(ctx->key_dec, KEY_LEN, 0) != KEY_LEN) {
		perror("getrandom(key_dec)");
		return -1;
	}

	if (getrandom(ctx->nonce, NONCE_LEN, 0) != NONCE_LEN) {
		perror("getrandom(nonce)");
		return -1;
	}

	return 0;
}

static void ovpn_rand_addr_port(char *addr, size_t alen, char *port, size_t plen)
{
	snprintf(addr, alen, "10.%u.%u.%u",
		stress_mwc8() + 1, stress_mwc8(), stress_mwc8() + 1);
	snprintf(port, plen, "%u",
		(stress_mwc16() % 64511) + 1024);
}

static int build_connect(struct ovpn_ctx *ovpn)
{
	char addr[INET_ADDRSTRLEN], port[6];

	ovpn_ctx_reset(ovpn);
	ovpn->cmd = CMD_CONNECT;

	ovpn_rand_addr_port(addr, sizeof(addr), port, sizeof(port));
	if (ovpn_parse_new_peer(ovpn, stress_mwc32() % 10, addr, port, NULL))
		return -1;

	ovpn->key_slot = OVPN_KEY_SLOT_PRIMARY;
	ovpn->key_id   = 0;
	ovpn->cipher   = OVPN_CIPHER_ALG_AES_GCM;
	ovpn->key_dir  = KEY_DIR_OUT;

	return ovpn_generate_key(ovpn);
}

static int build_new_peer(struct ovpn_ctx *ovpn)
{
	char addr[INET_ADDRSTRLEN], port[6];

	ovpn_ctx_reset(ovpn);
	ovpn->cmd = CMD_NEW_PEER;
	ovpn->lport = 1194;

	ovpn_rand_addr_port(addr, sizeof(addr), port, sizeof(port));
	return ovpn_parse_new_peer(ovpn, stress_mwc32() % 10, addr, port, NULL);
}

static int build_set_peer(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);

	ovpn->cmd = CMD_SET_PEER;
	ovpn->peer_id = stress_mwc32() % 10;
	ovpn->keepalive_interval = 10;
	ovpn->keepalive_timeout  = 60;

	return 0;
}

static int build_del_peer(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);
	ovpn->cmd = CMD_DEL_PEER;
	ovpn->peer_id = stress_mwc32() % 10;
	return 0;
}

static int build_get_peer(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);
	ovpn->cmd = CMD_GET_PEER;
	ovpn->peer_id = stress_mwc32() % 10;
	return 0;
}

static int build_new_key(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);

	ovpn->cmd = CMD_NEW_KEY;
	ovpn->peer_id = stress_mwc32() % 10;
	ovpn->key_slot = OVPN_KEY_SLOT_PRIMARY;
	ovpn->key_id = 0;
	ovpn->cipher = OVPN_CIPHER_ALG_AES_GCM;
	ovpn->key_dir = KEY_DIR_OUT;

	return ovpn_generate_key(ovpn);
}

static int build_del_key(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);

	ovpn->cmd = CMD_DEL_KEY;
	ovpn->peer_id = stress_mwc32() % 10;
	ovpn->key_slot = OVPN_KEY_SLOT_PRIMARY;

	return 0;
}

static int build_get_key(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);

	ovpn->cmd = CMD_GET_KEY;
	ovpn->peer_id = stress_mwc32() % 10;
	ovpn->key_slot = OVPN_KEY_SLOT_PRIMARY;

	return 0;
}

static int build_swap_keys(struct ovpn_ctx *ovpn)
{
	ovpn_ctx_reset(ovpn);
	ovpn->cmd = CMD_SWAP_KEYS;
	ovpn->peer_id = stress_mwc32() % 10;
	return 0;
}

static int ovpn_autofill_args(struct ovpn_ctx *ovpn)
{
	switch (ovpn->cmd) {
	case CMD_NEW_IFACE:   return build_new_iface(ovpn);
	case CMD_CONNECT:     return build_connect(ovpn);
	case CMD_NEW_PEER:    return build_new_peer(ovpn);
	case CMD_SET_PEER:    return build_set_peer(ovpn);
	case CMD_DEL_PEER:    return build_del_peer(ovpn);
	case CMD_GET_PEER:    return build_get_peer(ovpn);
	case CMD_NEW_KEY:     return build_new_key(ovpn);
	case CMD_DEL_KEY:     return build_del_key(ovpn);
	case CMD_GET_KEY:     return build_get_key(ovpn);
	case CMD_SWAP_KEYS:   return build_swap_keys(ovpn);
	default:
		return 0;
	}
}

static int stress_ovpn(stress_args_t *args)
{
	struct ovpn_ctx ovpn;
	int last_cmd = -1;
	static const enum ovpn_cmd cmds[] = {
		CMD_INVALID, CMD_NEW_IFACE,
		CMD_CONNECT, CMD_NEW_PEER,
		CMD_SET_PEER, CMD_DEL_PEER,
		CMD_GET_PEER, CMD_NEW_KEY,
		CMD_DEL_KEY, CMD_GET_KEY,
		CMD_SWAP_KEYS,
	};
	const size_t count = SIZEOF_ARRAY(cmds);

	(void)memset(&ovpn, 0, sizeof(ovpn));
	ovpn.sa_family = AF_INET;
	ovpn.cipher = OVPN_CIPHER_ALG_NONE;
	ovpn.peers_file = NULL;
	ovpn.socket = -1;

	stress_proc_state_set(args->name, STRESS_STATE_SYNC_WAIT);
	stress_sync_start_wait(args);
	stress_proc_state_set(args->name, STRESS_STATE_RUN);

	do {
		int cmd;

		do {
			uint32_t idx = stress_mwc32() % count;

			cmd = cmds[idx];
		} while (cmd == last_cmd && count > 1);

		last_cmd = cmd;
		ovpn.cmd = cmd;

		ovpn_autofill_args(&ovpn);

		if (ovpn_run_cmd(&ovpn) != 0)
			shim_sched_yield();

		stress_bogo_inc(args);
	} while (stress_continue(args));

	stress_proc_state_set(args->name, STRESS_STATE_DEINIT);

	if (ovpn.socket >= 0)
		(void)close(ovpn.socket);

	return EXIT_SUCCESS;
}

const stressor_info_t stress_ovpn_info = {
	.stressor = stress_ovpn,
	.supported = stress_ovpn_supported,
	.classifier = CLASS_NETWORK | CLASS_OS,
	.verify = VERIFY_NONE,
	.help = help
};


#else

const stressor_info_t stress_ovpn_info = {
	.stressor = stress_unimplemented,
	.classifier = CLASS_NETWORK | CLASS_OS,
	.verify = VERIFY_NONE,
	.help = help,
	.unimplemented_reason = "built without libnl3 or linux/ovpn.h support"
};

#endif /* HAVE_LIB_NL && HAVE_LINUX_OVPN_H */
