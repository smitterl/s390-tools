#!/bin/bash

cu=$USER
sudo insmod /home/${cu}/linux/drivers/s390/char/uvdevice.ko
sudo chown $cu:$cu /dev/uv
ls -lh --color=auto /dev/uv
echo "press enter to unload module"
read ignore
sudo rmmod uvdevice.ko
