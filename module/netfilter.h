#ifndef _UAPI__LINUX_NETFILTER_H
#define _UAPI__LINUX_NETFILTER_H

#include <linux/if.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/sysctl.h>
#include <linux/kernel.h>


/* Responses from hook functions. */
#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4


enum nf_inet_hooks {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS
};

enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_INET   =  1,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO,
};

#ifndef _LINUX_NETFILTER_H
#define _LINUX_NETFILTER_H

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
};

static inline void nf_hook_state_init(struct nf_hook_state *p,
                                      unsigned int hook,
                                      int thresh,
                                      u_int8_t pf,
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
    nf_hookfn *hook;
    struct module *owner;
    void *priv;
    u_int8_t pf;
    unsigned int hooknum;
    int priority;
};


int nf_register_sockopt(struct nf_sockopt_ops *reg);
void nf_unregister_sockopt(struct nf_sockopt_ops *reg);

extern struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];

static inline int nf_hook(u_int8_t pf,
                          unsigned int hook,
                          struct sock *sk,
                          struct sk_buff *skb,
                          struct net_device *indev,
                          struct net_device *outdev,
                          int (*okfn)(struct sock *, struct sk_buff *)) {
    return 1;
}

#endif /* _LINUX_NETFILTER_H */
#endif
