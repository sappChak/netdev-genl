obj-m += nl_kernel.o
nl_kernel-objs := kernel/nl_kernel.o

EXTRA_CFLAGS = -I$(PWD)/include/
COMMON_INCLUDE=include

all: kernel-module-uninstall kernel-clean-ring-buffer kernel-build kernel-clean-temporary kernel-module-install user-build
	@tput setaf 3
	@echo "    done: all"
	@tput sgr0

clean: kernel-module-uninstall kernel-clean user-clean
	@tput setaf 3
	@echo "    done: clean"
	@tput sgr0

kernel-build:
	@tput setaf 1
	@echo "    kernel-build"
	@tput sgr0
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

kernel-clean:
	@tput setaf 1
	@echo "    kernel-clean"
	@tput sgr0
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

kernel-clean-temporary:
	@tput setaf 1
	@echo "    kernel-clean-temporary"
	@tput sgr0
	-rm -rf *.o *~ core .depend .*.cmd *.mod.c .tmp_versions
	-rm -rf kernel/*.o kernel/*~ kernel/core kernel/.depend kernel/.*.cmd kernel/*.mod.c kernel/.tmp_versions
	-rm -rf Module.symvers modules.order

kernel-module-install:
	@tput setaf 1
	@echo "    kernel-module-install"
	@tput sgr0
	-sudo insmod nl_kernel.ko

kernel-module-uninstall:
	@tput setaf 1
	@echo "    kernel-module-uninstall"
	@tput sgr0
	-sudo rmmod nl_kernel

kernel-clean-ring-buffer:
	@tput setaf 1
	@echo "    kernel-clean-ring-buffer"
	@tput sgr0
	sudo dmesg -c > /dev/null

user-build:
	@tput setaf 1
	@echo "    user-build"
	@tput sgr0
	gcc -Wall -Werror user/nl_user.c user/nl_parse.c -o nl_user.out -I$(COMMON_INCLUDE)

user-clean:
	@tput setaf 1
	@echo "    user-clean"
	@tput sgr0
	rm -rf *.out
