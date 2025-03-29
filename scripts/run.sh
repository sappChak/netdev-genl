#!/bin/bash

# Check if the module exists
if ! modinfo netlink_kernel.ko &>/dev/null; then
        echo "Module netlink_kernel.ko not found!"
        exit 1
fi

# Insert the module
sudo insmod netlink_kernel.ko

# Verify if the module was inserted
if ! lsmod | grep -q netlink_kernel; then
        echo "Failed to insert netlink_kernel module"
        exit 1
fi

# Show relevant kernel messages
sudo dmesg | grep netlink_kernel | tail

# Remove the module
sudo rmmod netlink_kernel

# Verify if the module was removed
if lsmod | grep -q netlink_kernel; then
        echo "Failed to remove netlink_kernel module"
        exit 1
fi

exit 0
