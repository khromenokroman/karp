###############################################################
# 	Makefile для создания модуля который работает с ARP
###############################################################

obj-m += ngfw_arp.o
PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
load:
	insmod ngfw_arp.ko
	dmesg -c
unload:
	rmmod ngfw_arp
	dmesg -c