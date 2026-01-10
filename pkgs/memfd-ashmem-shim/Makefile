obj-m += src/memfd_ashmem_shim.o

USER  := $(shell whoami)
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

all: build

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) M=$(PWD) INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: load all install