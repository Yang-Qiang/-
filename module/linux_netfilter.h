#ifndef __LINUX_NETFILTER_H
#define __LINUX_NETFILTER_H

#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <uapi/linux/netfilter.h>
#ifdef CONFIG_NETFILTER

/* Largest hook number + 1 */
#define NF_MAX_HOOKS 8

struct sk_buff;

struct nf_hook_ops;

struct sock;

struct nf_hook_state {
	size_t size;
	unsigned int hook;
	int thresh;
	u_int8_t pf;
	struct net_device *in;
	struct net_device *out;
	struct sock *sk;
	int (*okfn)(struct sock *, struct sk_buff *);
	/* RHEL: this structure can be extended by adding new fields below
	 * this point. Any user of such new field has to check the 'size'
	 * field first to determine whether the field is present. */
};

static inline void nf_hook_state_init(struct nf_hook_state *p,
				      unsigned int hook,
				      int thresh, u_int8_t pf,
				      struct net_device *indev,
				      struct net_device *outdev,
				      struct sock *sk,
				      int (*okfn)(struct sock *, struct sk_buff *));


typedef unsigned int nf_hookfn(const struct nf_hook_ops *ops,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
#ifndef __GENKSYMS__
			       const struct nf_hook_state *state
#else
			       int (*okfn)(struct sk_buff *)
#endif
			       );

struct nf_hook_ops {
	struct list_head list;

	/* User fills in from here down. */
	nf_hookfn	*hook;
	struct module	*owner;
	void		*priv;
	u_int8_t	pf;
	unsigned int	hooknum;
	/* Hooks are ordered in ascending priority. */
	int		priority;
};



/* Function to register/unregister hook points. */
int nf_register_hook(struct nf_hook_ops *reg);
void nf_unregister_hook(struct nf_hook_ops *reg);
int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n);
void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n);

/* Functions to register get/setsockopt ranges (non-inclusive).  You
   need to check permissions yourself! */
int nf_register_sockopt(struct nf_sockopt_ops *reg);
void nf_unregister_sockopt(struct nf_sockopt_ops *reg);

extern struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];

#if defined(CONFIG_JUMP_LABEL)
#include <linux/static_key.h>
extern struct static_key nf_hooks_needed[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
static inline bool nf_hooks_active(u_int8_t pf, unsigned int hook)
{
	if (__builtin_constant_p(pf) &&
	    __builtin_constant_p(hook))
		return static_key_false(&nf_hooks_needed[pf][hook]);

	return !list_empty(&nf_hooks[pf][hook]);
}
#else
static inline bool nf_hooks_active(u_int8_t pf, unsigned int hook)
{
	return !list_empty(&nf_hooks[pf][hook]);
}
#endif

int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state);

/**
 *	nf_hook_thresh - call a netfilter hook
 *	
 *	Returns 1 if the hook has allowed the packet to pass.  The function
 *	okfn must be invoked by the caller in this case.  Any other return
 *	value indicates the packet has been consumed by the hook.
 */
static inline int nf_hook_thresh(u_int8_t pf, unsigned int hook,
				 struct sock *sk,
				 struct sk_buff *skb,
				 struct net_device *indev,
				 struct net_device *outdev,
				 int (*okfn)(struct sock *, struct sk_buff *),
				 int thresh)
{
	if (nf_hooks_active(pf, hook)) {
		struct nf_hook_state state;

		nf_hook_state_init(&state, hook, thresh, pf,
				   indev, outdev, sk, okfn);
		return nf_hook_slow(skb, &state);
	}
	return 1;
}

static inline int nf_hook(u_int8_t pf, unsigned int hook, struct sock *sk,
			  struct sk_buff *skb, struct net_device *indev,
			  struct net_device *outdev,
			  int (*okfn)(struct sock *, struct sk_buff *))
{
	return nf_hook_thresh(pf, hook, sk, skb, indev, outdev, okfn, INT_MIN);
}
                   
/* Activate hook; either okfn or kfree_skb called, unless a hook
   returns NF_STOLEN (in which case, it's up to the hook to deal with
   the consequences).

   Returns -ERRNO if packet dropped.  Zero means queued, stolen or
   accepted.
*/

/* RR:
   > I don't want nf_hook to return anything because people might forget
   > about async and trust the return value to mean "packet was ok".

   AK:
   Just document it clearly, then you can expect some sense from kernel
   coders :)
*/

static inline int
NF_HOOK_THRESH(uint8_t pf, unsigned int hook, struct sock *sk,
	       struct sk_buff *skb, struct net_device *in,
	       struct net_device *out,
	       int (*okfn)(struct sock *, struct sk_buff *), int thresh)
{
	int ret = nf_hook_thresh(pf, hook, sk, skb, in, out, okfn, thresh);
	if (ret == 1)
		ret = okfn(sk, skb);
	return ret;
}

static inline int
NF_HOOK_COND(uint8_t pf, unsigned int hook, struct sock *sk,
	     struct sk_buff *skb, struct net_device *in, struct net_device *out,
	     int (*okfn)(struct sock *, struct sk_buff *), bool cond)
{
	int ret;

	if (!cond ||
	    ((ret = nf_hook_thresh(pf, hook, sk, skb, in, out, okfn, INT_MIN)) == 1))
		ret = okfn(sk, skb);
	return ret;
}

static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct sock *, struct sk_buff *))
{
	return NF_HOOK_THRESH(pf, hook, sk, skb, in, out, okfn, INT_MIN);
}

/* Call setsockopt() */
int nf_setsockopt(struct sock *sk, u_int8_t pf, int optval, char __user *opt,
		  unsigned int len);
int nf_getsockopt(struct sock *sk, u_int8_t pf, int optval, char __user *opt,
		  int *len);
#ifdef CONFIG_COMPAT
int compat_nf_setsockopt(struct sock *sk, u_int8_t pf, int optval,
		char __user *opt, unsigned int len);
int compat_nf_getsockopt(struct sock *sk, u_int8_t pf, int optval,
		char __user *opt, int *len);
#endif

/* Call this before modifying an existing packet: ensures it is
   modifiable and linear to the point you care about (writable_len).
   Returns true or false. */
int skb_make_writable(struct sk_buff *skb, unsigned int writable_len);

struct flowi;
struct nf_queue_entry;

struct nf_afinfo {
	unsigned short	family;
	__sum16		(*checksum)(struct sk_buff *skb, unsigned int hook,
				    unsigned int dataoff, u_int8_t protocol);
	__sum16		(*checksum_partial)(struct sk_buff *skb,
					    unsigned int hook,
					    unsigned int dataoff,
					    unsigned int len,
					    u_int8_t protocol);
	int		(*route)(struct net *net, struct dst_entry **dst,
				 struct flowi *fl, bool strict);
	void		(*saveroute)(const struct sk_buff *skb,
				     struct nf_queue_entry *entry);
	int		(*reroute)(struct sk_buff *skb,
				   const struct nf_queue_entry *entry);
	int		route_key_size;
};

extern const struct nf_afinfo __rcu *nf_afinfo[NFPROTO_NUMPROTO];
static inline const struct nf_afinfo *nf_get_afinfo(unsigned short family)
{
	return rcu_dereference(nf_afinfo[family]);
}

static inline __sum16
nf_checksum(struct sk_buff *skb, unsigned int hook, unsigned int dataoff,
	    u_int8_t protocol, unsigned short family)
{
	const struct nf_afinfo *afinfo;
	__sum16 csum = 0;

	rcu_read_lock();
	afinfo = nf_get_afinfo(family);
	if (afinfo)
		csum = afinfo->checksum(skb, hook, dataoff, protocol);
	rcu_read_unlock();
	return csum;
}

static inline __sum16
nf_checksum_partial(struct sk_buff *skb, unsigned int hook,
		    unsigned int dataoff, unsigned int len,
		    u_int8_t protocol, unsigned short family)
{
	const struct nf_afinfo *afinfo;
	__sum16 csum = 0;

	rcu_read_lock();
	afinfo = nf_get_afinfo(family);
	if (afinfo)
		csum = afinfo->checksum_partial(skb, hook, dataoff, len,
						protocol);
	rcu_read_unlock();
	return csum;
}

int nf_register_afinfo(const struct nf_afinfo *afinfo);
void nf_unregister_afinfo(const struct nf_afinfo *afinfo);

#include <net/flow.h>
extern void (*nf_nat_decode_session_hook)(struct sk_buff *, struct flowi *);

static inline void
nf_nat_decode_session(struct sk_buff *skb, struct flowi *fl, u_int8_t family)
{
#ifdef CONFIG_NF_NAT_NEEDED
	void (*decodefn)(struct sk_buff *, struct flowi *);

	rcu_read_lock();
	decodefn = rcu_dereference(nf_nat_decode_session_hook);
	if (decodefn)
		decodefn(skb, fl);
	rcu_read_unlock();
#endif
}

#else /* !CONFIG_NETFILTER */
#define NF_HOOK(pf, hook, sk, skb, indev, outdev, okfn) (okfn)(sk, skb)
#define NF_HOOK_COND(pf, hook, sk, skb, indev, outdev, okfn, cond) (okfn)(sk, skb)
static inline int nf_hook_thresh(u_int8_t pf, unsigned int hook,
				 struct sock *sk,
				 struct sk_buff *skb,
				 struct net_device *indev,
				 struct net_device *outdev,
				 int (*okfn)(struct sock *sk, struct sk_buff *), int thresh)
{
	return okfn(sk, skb);
}
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct sock *sk,
			  struct sk_buff *skb, struct net_device *indev,
			  struct net_device *outdev,
			  int (*okfn)(struct sock *, struct sk_buff *))
{
	return 1;
}
struct flowi;
static inline void
nf_nat_decode_session(struct sk_buff *skb, struct flowi *fl, u_int8_t family)
{
}
#endif /*CONFIG_NETFILTER*/


#endif /* __LINUX_NETFILTER_H */
