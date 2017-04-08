#ifndef _FILE_H
#define _FILE_H
#include <linux/fs.h>

int mem_open(struct inode* inode, struct file* filp);
int mem_release(struct inode* inode, struct file* filp);
long memdev_ioctl(struct file* filp, unsigned int cmd, unsigned long arg);

#endif
