#include <linux/compiler.h>
#include <linux/if.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/sysctl.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "linux_in.h"
#include "linux_netfilter.h"

static inline void nf_hook_state_init(struct nf_hook_state *p,
                                      unsigned int hook,
                                      int thresh,
                                      u_int8_t pf,
                                      struct net_device *indev,
                                      struct net_device *outdev,
                                      struct sock *sk,
                                      int (*okfn)(struct sock *, struct sk_buff *)) {
    p->size = sizeof(*p);
    p->hook = hook;
    p->thresh = thresh;
    p->pf = pf;
    p->in = indev;
    p->out = outdev;
    p->sk = sk;
    p->okfn = okfn;
}

static inline void nf_hook_state_init(struct nf_hook_state *p,
                                      unsigned int hook,
                                      int thresh,
                                      u_int8_t pf,
                                      struct net_device *indev,
                                      struct net_device *outdev,
                                      struct sock *sk,
                                      int (*okfn)(struct sock *, struct sk_buff *)) {
    p->size = sizeof(*p);
    p->hook = hook;
    p->thresh = thresh;
    p->pf = pf;
    p->in = indev;
    p->out = outdev;
    p->sk = sk;
    p->okfn = okfn;
}