#ifndef _LINUX_IP_H
#define _LINUX_IP_H

#include <asm/byteorder.h>
#include <linux/skbuff.h>
#include <linux/types.h>

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 ihl : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version : 4, ihl : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
    /*The options start here. */
};

static inline struct iphdr *ip_hdr(const struct sk_buff *skb) {
    return (struct iphdr *) skb_network_header(skb);
}

#endif
