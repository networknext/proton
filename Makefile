
obj-m += proton.o

module: proton.h proton.c hydrogen.c hydrogen.h
	@echo building proton kernel module
	sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
	rm -f *.o
	rm -f *.ko
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	sudo rmmod -f proton >/dev/null 2>&1; echo
	sudo insmod proton.ko; echo
