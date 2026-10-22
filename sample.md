#!/bin/bash

timedatectl set-ntp true
USERNAME=pix
# PASSWORD is exported by naGINI: it is the script ID (last URL path segment). It is set as the
# initial password below and expired, so it must be changed at the first login.
# Script output is logged to /var/log/naGINI_*.log on the installed system - never echo secrets.

sgdisk -o ${DISK}
sgdisk -n 1:0:1024MiB ${DISK}
sgdisk -t 1:ef00 ${DISK}
sgdisk -n 2 ${DISK}
sgdisk -t 2:8300 ${DISK}
sgdisk -p ${DISK}

mkfs.fat -F32 ${DISK}1
mkfs.ext4 -F ${DISK}2

mount ${DISK}2 /mnt/
mkdir /mnt/boot/
mount ${DISK}1 /mnt/boot/

# Install packages including UKI tools
pacstrap /mnt base linux linux-firmware vim firewalld systemd-ukify openssh sudo qemu-guest-agent

# Generate fstab
genfstab -U /mnt >> /mnt/etc/fstab


# Chroot into new system
# set timezone
arch-chroot /mnt sh -c 'ln -sf /usr/share/zoneinfo/UTC /etc/localtime'
# configure locale
arch-chroot /mnt sh -c 'echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen'
arch-chroot /mnt sh -c 'locale-gen'
arch-chroot /mnt sh -c 'echo "LANG=en_US.UTF-8" > /etc/locale.conf'
# Set hostname
arch-chroot /mnt sh -c 'echo "nagini-arch-" > /etc/hostname'
# add second user
arch-chroot /mnt sh -c 'sed -i "s/^# %wheel ALL=(ALL:ALL) ALL$/%wheel ALL=(ALL:ALL) ALL/" /etc/sudoers'
arch-chroot /mnt sh -c "useradd -G wheel $USERNAME"
arch-chroot /mnt sh -c "echo $USERNAME:$PASSWORD | chpasswd"
arch-chroot /mnt sh -c "passwd -e $USERNAME"
arch-chroot /mnt sh -c "mkdir -p /home/$USERNAME/.ssh"
arch-chroot /mnt sh -c "chown $USERNAME:$USERNAME -R /home/$USERNAME/"
# install systemd bootmgr
arch-chroot /mnt sh -c 'bootctl install'

arch-chroot /mnt sh -c 'systemctl enable systemd-networkd'
arch-chroot /mnt sh -c 'systemctl enable systemd-resolved'
arch-chroot /mnt sh -c 'systemctl enable firewalld'
arch-chroot /mnt sh -c 'systemctl enable sshd'

arch-chroot /mnt sh -c 'ukify build --linux=/boot/vmlinuz-linux --initrd=/boot/initramfs-linux.img --cmdline="root='${DISK}'2 debug systemd.log_level=debug" --output=/boot/EFI/Linux/arch-linux.efi'

# Main bootloader configuration
cat > /mnt/boot/loader/loader.conf << EOF
default arch-linux.efi
timeout 3
console-mode keep
editor no
auto-entries no
EOF

# Create loader entry for UKI
cat > /mnt/boot/loader/entries/arch-linux.conf << EOF
title   Arch Linux
efi     /EFI/Linux/arch-linux.efi
EOF

# Create default network configuration
cat > /mnt//etc/systemd/network/10-${INTERFACE}.network << EOF
[Match]
Name=${INTERFACE}

[Network]
DHCP=yes
IPForward=no
IPv6AcceptRA=yes

[DHCP]
UseDNS=yes
UseNTP=yes
UseRoutes=yes
EOF

umount -R /mnt/

reboot

