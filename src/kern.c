#include <linux/module.h>
#include <linux/net.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>

#include <linux/tcp.h>

#include <net/netlink.h>
#include <net/tcp.h>

struct tcp_info_extended
{
	struct tcp_info *base;
	int ino_number;
};

#define IPPROTO_TCP_EXT 7


static void tcp_get_extended_info(struct sock *sk, struct tcp_info_extended *info)
{
	tcp_get_info(sk, info->base);
	info->ino_number = SOCK_INODE(sk->sk_socket)->i_ino;
}

static void tcp_diag_get_info(struct sock *sk, struct inet_diag_msg *r,
			      void *_info)
{
	struct tcp_info_extended *info = _info;

	if (inet_sk_state_load(sk) == TCP_LISTEN) {
		r->idiag_rqueue = READ_ONCE(sk->sk_ack_backlog);
		r->idiag_wqueue = READ_ONCE(sk->sk_max_ack_backlog);
	} else if (sk->sk_type == SOCK_STREAM) {
		const struct tcp_sock *tp = tcp_sk(sk);

		r->idiag_rqueue = max_t(int, READ_ONCE(tp->rcv_nxt) -
					     READ_ONCE(tp->copied_seq), 0);
		r->idiag_wqueue = READ_ONCE(tp->write_seq) - tp->snd_una;
	}
	if (info) {
		tcp_get_extended_info(sk, info);
	}
}


static void tcp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			  const struct inet_diag_req_v2 *r)
{
	struct inet_hashinfo *hinfo;

	hinfo = sock_net(cb->skb->sk)->ipv4.tcp_death_row.hashinfo;

	inet_diag_dump_icsk(hinfo, skb, cb, r);
}


static const struct inet_diag_handler tcp_diag_handler = {
	.dump			= tcp_diag_dump,
	.idiag_get_info		= tcp_diag_get_info,
	.idiag_type		= IPPROTO_TCP_EXT, //IPPROTO_TCP,
	.idiag_info_size	= sizeof(struct tcp_info_extended),
};

static int __init tcp_diag_init(void)
{
	return inet_diag_register(&tcp_diag_handler);
}

static void __exit tcp_diag_exit(void)
{
	inet_diag_unregister(&tcp_diag_handler);
}

module_init(tcp_diag_init);
module_exit(tcp_diag_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-7 /* AF_INET - IPPROTO_TCP_EXT */);