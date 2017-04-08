//
// Created by yq on 17-2-21.
//

#ifndef NETFILTER_FILTER_H
#define NETFILTER_FILTER_H
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING 0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN 1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD 2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT 3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING 4
#define NF_IP_NUMHOOKS 5
#endif
