#include "file.h"
#include <asm/uaccess.h>
#include <linux/fs.h>
#include "common.h"

#define MAX_NR 100  //能过滤的IP地址数量，port数量

extern unsigned int* deny_ip;
extern unsigned short* deny_port;
extern int flag;
int mem_open(struct inode* inode, struct file* filp) { return 0; }



int mem_release(struct inode* inode, struct file* filp) { return 0; }

long memdev_ioctl(struct file* filp, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    int ioarg = 0;
    int i;

    printk(KERN_DEBUG "in memdev ioctl\n");

    switch (cmd) {
        case 0:
            get_user(ioarg, (int*) arg);
            for (i = 0; i < MAX_NR; i++) {
                if (*(deny_ip + i) == 0) {
                    *(deny_ip + i) = ioarg;
                    flag = 0;
                    printk(KERN_DEBUG "-----------ADD_IP---------%x-----\n", htonl(*(deny_ip + i)));
                    break;
                }
            }
            break;
        case 1:
            get_user(ioarg, (int*) arg);
            for (i = 0; i < MAX_NR; i++) {
                if (*(deny_ip + i) == ioarg) {
                    *(deny_ip + i) = 0;
                    flag = 0;
                    printk(KERN_DEBUG "-----------DEL_IP----------%x----\n", htonl(ioarg));
                    break;
                }
            }
            break;
        case 3:
            get_user(ioarg, (int*) arg);
            for (i = 0; i < MAX_NR; i++) {
                if (*(deny_port + i) == 0) {
                    *(deny_port + i) = ioarg;
                    flag = 1;
                    printk(KERN_DEBUG "---------ADD_PORT--------%d-----\n", *(deny_port + i));
                    break;
                }
            }
            break;
        case 4:
            get_user(ioarg, (int*) arg);
            for (i = 0; i < MAX_NR; i++) {
                if (*(deny_port + i) == ioarg)
                    ;
                {
                    *(deny_port + i) = 0;
                    flag = 1;
                    printk(KERN_DEBUG "--------DEL_PORT-------%d-----\n", ioarg);
                    break;
                }
            }
            break;
        default:
            printk(KERN_DEBUG "--------CMD is error---------\n");
            return -ENOTTY;
    }
    return ret;
}

/*文件操作结构体*/
struct file_operations netfilter_fops = {
    .open = mem_open, .release = mem_release, .unlocked_ioctl = memdev_ioctl,
};
