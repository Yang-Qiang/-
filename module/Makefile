CURRENT_PATH := $(shell pwd)             #当前所在的路径
LINUX_KERNEL := $(shell uname -r)        #内核的版本号


obj-m += filter.o

filter-objs := module.o file.o check.o

#内核代码所在的路径
LINUX_KERNEL_PATH :=/usr/src/kernels/3.10.0-514.10.2.el7.x86_64

#编译
all:
	make -C $(LINUX_KERNEL_PATH) M=${CURRENT_PATH} modules

#清除编译生成的文件
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
