#ifndef __LINUX_NETFILTER_H
#define __LINUX_NETFILTER_H

#include <linux/if.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
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

    /* User fills in from here down. */
    nf_hookfn *hook;
    struct module *owner;
    void *priv;
    u_int8_t pf;
    unsigned int hooknum;
    /* Hooks are ordered in ascending priority. */
    int priority;
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
static inline bool nf_hooks_active(u_int8_t pf, unsigned int hook) {
    if (__builtin_constant_p(pf) && __builtin_constant_p(hook))
        return static_key_false(&nf_hooks_needed[pf][hook]);

    return !list_empty(&nf_hooks[pf][hook]);
}
#else
static inline bool nf_hooks_active(u_int8_t pf, unsigned int hook) {
    return !list_empty(&nf_hooks[pf][hook]);
}
#endif

int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state);

static inline int nf_hook(u_int8_t pf,
                          unsigned int hook,
                          struct sock *sk,
                          struct sk_buff *skb,
                          struct net_device *indev,
                          struct net_device *outdev,
                          int (*okfn)(struct sock *, struct sk_buff *)) {
    return nf_hook_thresh(pf, hook, sk, skb, indev, outdev, okfn, INT_MIN);
}

#else  /* !CONFIG_NETFILTER */

static inline int nf_hook(u_int8_t pf,
                          unsigned int hook,
                          struct sock *sk,
                          struct sk_buff *skb,
                          struct net_device *indev,
                          struct net_device *outdev,
                          int (*okfn)(struct sock *, struct sk_buff *)) {
    return 1;
}
#endif /*CONFIG_NETFILTER*/

#endif /* __LINUX_NETFILTER_H */
