#!/bin/bash

## isolcpu.sh takes the new 'isolcpu' value and applies it to /etc/default/grub
##
## The script prompts for confirmation, to disable confirmation add [-y]
##
## successful output:

# [vastdata@csmkfs-qlc-cn2 tmp]$ ./isolcpu.sh '4,5,6-17,24,25,26-37' -y
# Current_cmdline=4,5,6-19,24,25,26-39
# New_cmdline=4,5,6-17,24,25,26-37
# Backup grub default
# '/etc/default/grub' -> '/etc/default/grub.backup'
# lable is B
# umount inactive
# mount inactive
# Backup grub config file
# '/tmp/inactive/boot/grub2/grub.cfg' -> '/tmp/inactive/boot/grub2/grub.cfg.backup'
# Updating isolcpu in grub default
# grub mkconfig
# Generating grub configuration file ...
# Found linux image: /boot/vmlinuz-3.10.0-1127.18.2.el7.vastos.9.x86_64
# Found initrd image: /boot/initramfs-3.10.0-1127.18.2.el7.vastos.9.x86_64.img
# Found linux image: /boot/vmlinuz-3.10.0-1062.12.1.el7.vastos.8.x86_64
# Found initrd image: /boot/initramfs-3.10.0-1062.12.1.el7.vastos.8.x86_64.img
# Found linux image: /boot/vmlinuz-0-rescue-98163e7634094acdb1a7f14ba902d3ad
# Found initrd image: /boot/initramfs-0-rescue-98163e7634094acdb1a7f14ba902d3ad.img
# Found linux image: /boot/vmlinuz-0-rescue-ec28a60897cbacd1dfecd5821f59fb01
# Found initrd image: /boot/initramfs-0-rescue-ec28a60897cbacd1dfecd5821f59fb01.img
# Found CentOS Linux release 7.7.1908 (Core) on /dev/sda2
# done
#         linux16 /boot/vmlinuz-3.10.0-1127.18.2.el7.vastos.9.x86_64 root=UUID=a18f61c4-dce7-4d7e-a195-ef94442ca2a3 ro panic=60 log_buf_len=10M nvme_core.max_retries=0 console=tty0 crashkernel=768M console=ttyS0,115200n8 nvme_core.io_timeout=6 nvme_core.admin_timeout=6 isolcpus=4,5,6-17,24,25,26-37
#         linux16 /boot/vmlinuz-3.10.0-1062.12.1.el7.vastos.8.x86_64 root=UUID=a18f61c4-dce7-4d7e-a195-ef94442ca2a3 ro panic=60 log_buf_len=10M nvme_core.max_retries=0 console=tty0 crashkernel=768M console=ttyS0,115200n8 nvme_core.io_timeout=6 nvme_core.admin_timeout=6 isolcpus=4,5,6-17,24,25,26-37
#         linux16 /boot/vmlinuz-0-rescue-98163e7634094acdb1a7f14ba902d3ad root=UUID=a18f61c4-dce7-4d7e-a195-ef94442ca2a3 ro panic=60 log_buf_len=10M nvme_core.max_retries=0 console=tty0 crashkernel=768M console=ttyS0,115200n8 nvme_core.io_timeout=6 nvme_core.admin_timeout=6 isolcpus=4,5,6-17,24,25,26-37
#         linux16 /boot/vmlinuz-0-rescue-ec28a60897cbacd1dfecd5821f59fb01 root=UUID=a18f61c4-dce7-4d7e-a195-ef94442ca2a3 ro panic=60 log_buf_len=10M nvme_core.max_retries=0 console=tty0 crashkernel=768M console=ttyS0,115200n8 nvme_core.io_timeout=6 nvme_core.admin_timeout=6 isolcpus=4,5,6-17,24,25,26-37
# Setting boot device B
# boot was successfully set to device label: B (one time=False)

if [[ ! $2 ]];
then
useConfirm=true
else
useConfirm=false
fi

confirm() {
   [ "$useConfirm" = true ] && read -p "Looks ok? enter to proceed (Enter) - (Add -y to disable confirmation) - (^C to abort)"
}

cmdline=$(cat /proc/cmdline | awk -Fisolcpus= '{print $2}' | awk '{print $1}')
grub_isolcpu=$(grep GRUB_CMDLINE_LINUX /etc/default/grub | awk -Fisolcpus= '{print $2}' | awk '{print $1}' | sed 's/"//g')
label=$(/usr/bin/vastos_tool list_block_devices | grep -w "mountpoint=/" | awk -F= '{print $3}' | awk '{print substr($1,1, length($1)-1)}')
cmdline_grub=$(grep GRUB_CMDLINE_LINUX /etc/default/grub)

echo -e "Current_proc_isolcpu=$cmdline"
echo -e "Current_grub_isolcpu=$grub_isolcpu"
echo -e "New_isolcpu=$1"
echo -e "Lable=$label"
echo -e "Current_grub_cmdline:\n"$cmdline_grub

confirm

if [[ ! $1 ]];
then
echo -e 'Please add isolcpu'
exit 1
fi

echo -e 'Backup grub default'
sudo cp -av --backup=numbered /etc/default/grub{,.backup}

if [[ $label == "A" ]];
then
echo -e 'lable is' $label
cfg_file=/boot/grub2/grub.cfg
part_label=A;
else
echo -e 'lable is' $label
echo -e 'umount inactive'
sudo umount /tmp/inactive
echo -e 'mount inactive'
sudo mount -L A /tmp/inactive
cfg_file='/tmp/inactive/boot/grub2/grub.cfg'
part_label=B
fi

echo -e "Checking current cfg_file $cfg_file"
sudo awk -F\' '$1=="menuentry " {print i++ " : " $2}' $cfg_file
if [[ $(sudo awk -F\' '$1=="menuentry " {print i++ " : " $2}' $cfg_file | grep $(uname -r) | wc -l) > 0 ]]; 
then
echo -e "Found current OS $(uname -r) in cfg file $cfg_file"
else
echo -e "Didn't find $(uname -r) in $cfg_file, note that"
fi

echo -e 'Backup grub config file'
sudo cp -av --backup=numbered "$cfg_file"{,.backup}

echo -e 'Updating isolcpu in grub default'
sudo sed -i s/$grub_isolcpu/$1/g /etc/default/grub

echo -e 'grub mkconfig'
sudo grub2-mkconfig -o "$cfg_file"

sudo grep 'isolcpus' "$cfg_file"

echo -e 'Setting boot device' $part_label
/usr/bin/vastos_tool set_boot_to_device "$part_label"

sync;sync

echo -e "Reboot pending: Done setting isolcpu $1 on partition $part_label cfg_file $cfg_file on host $(hostname)"
