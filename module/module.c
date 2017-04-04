// Created by yq on 17-2-21.
//
#include "module.h"
#include <asm/errno.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>    //kmalloc>
#include <linux/string.h>  //memset
#include "check.h"
#include "file.h"
#include "linux_in.h"

unsigned int *deny_ip = NULL;
unsigned short *deny_port = NULL;
int flag = -1;  //过滤标志 0：IP过滤 1：port过滤

/* After promisc drops, checksum checks. */
#define MAX_NR 100  //能过滤的IP地址数量，port数量
int mem_major = 0;

struct cdev cdev;

extern struct file_operations netfilter_fops;

/*declare five hooks*/
// const char* hooks = {"NF_IP_PRE_ROUTR", "NF_IP_LOCAL_IN", "NF_IP_FORWARD",
// "NF_IP_LOCAL_IN",
//  "NF_IP_POST_ROUTE"};

/*Realization of hook function */
unsigned int packet_filter(unsigned int hooknum,
                           struct sk_buff *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *)) {
    int ret = NF_DROP;
    if (skb == NULL) {
        printk("%s\n", "*skb is NULL");
        return NF_ACCEPT;
    }

    if (flag == 0) {
        ret = check_ip_packet(skb);
        if (ret != NF_ACCEPT) {
            return ret;
        }
    }
    else if (flag == 1) {
        ret = check_port_packet(skb);
        if (ret != NF_ACCEPT) return ret;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops packet_filter_opt = {
    .hook = packet_filter,
    // .owner = THIS_MODULE,
    .pf = PF_INET,                  /*IPv4 protocol hook*/
    .hooknum = NF_INET_PRE_ROUTING, /*First stage hook*/
    .priority = NF_IP_PRI_FIRST,    /*Hook to come first*/
};

/*netfilter init module */
static int filter_init(void) {
    int err;
    int result = 0;
    dev_t devno;

    /*Regiser the control device, /dev/netfilter */
    if (mem_major) {
        result = register_chrdev_region(devno, 1, "filter");
    }
    else {
        result = alloc_chrdev_region(&devno, 0, 1, "filter");
        mem_major = MAJOR(devno);
    }

    if (result < 0) return result;

    //初始化cdev结构，并传递file_operations结构指针。
    devno = MKDEV(mem_major, 0);
    printk(KERN_DEBUG "-----major is %d-----------\n", MAJOR(devno));
    printk(KERN_DEBUG "-----minor is %d-----------\n", MINOR(devno));
    cdev_init(&cdev, &netfilter_fops);
    cdev.owner = THIS_MODULE;
    cdev.ops = &netfilter_fops;

    //注册字符设备。
    err = cdev_add(&cdev, MKDEV(mem_major, 0), 1);
    if (err != 0) {
        printk(KERN_DEBUG "--------cdev_add error--------\n");
    }

    printk(KERN_DEBUG "netfilter: Control device successfully registered.\n");

    /*Register the network hooks*/
    nf_register_hook(&packet_filter_opt);
    // nf_register_hooks(packet_filter_opt, ARRAY_SIZE(packet_filter_opt));
    // register hook
    printk(KERN_DEBUG "netfilter: Network hooks successfully installed.\n");

    deny_ip = (unsigned int *) kmalloc(sizeof(unsigned int) * MAX_NR, GFP_KERNEL);
    deny_port = (unsigned short *) kmalloc(sizeof(unsigned short) * MAX_NR, GFP_KERNEL);

    if ((deny_ip == NULL) || (deny_port == NULL)) {
        return -ENOMEM;  // ENOMEM：Out of memory
        goto fail_malloc;
    }
    memset(deny_ip, 0, sizeof(unsigned int) * MAX_NR);
    memset(deny_port, 0, sizeof(unsigned short) * MAX_NR);

fail_malloc:
    unregister_chrdev_region(MKDEV(mem_major, 0), 2);

    printk(KERN_DEBUG "netfilter: Module installation successful.\n");

    return 0;
}

/*netfilter exit module*/
static void filter_exit(void) {
    /* Remove IPV4 hook
  *nf_unregister_hooks(packet_filter_opt, ARRAY_SIZE(packet_filter_opt));
  * unregister hook
  */
    nf_unregister_hook(&packet_filter_opt);

    //注销设备
    cdev_del(&cdev);
    unregister_chrdev_region(MKDEV(mem_major, 0), 2);

    //释放设备结构体内存
    kfree(deny_ip);
    kfree(deny_port);

    printk(KERN_DEBUG "netfilter:Remove of Module from Kernel successful!.\n");
}

MODULE_LICENSE("GPL");
module_init(filter_init);  // insmod module
module_exit(filter_exit);  // rmmod module
