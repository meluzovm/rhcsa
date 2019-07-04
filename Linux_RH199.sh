#MANUAL
#The standard sections of the manual include:
#1   Executable programs or shell commands
#2   System calls (functions provided by the kernel)
#3   Library calls (functions within program libraries)
#4   Special files (usually found in /dev)
#5   File formats and conventions eg /etc/passwd
#6   Games
#7   Miscellaneous (including macro packages and conventions), e.g. man(7), groff(7)
#8   System administration commands (usually only for root)
#9   Kernel routines [Non standard]
man 8 mount
man -k '^mount'                                                                #Show all chapters in manual for specific command
man man-pages
man -wK somesearch                                                                 #search all man pages fro specific word

################################################################################
#Language
################################################################################
locale                                                                           #current LANG Settings
localectl                                                                        #current LANG Settings
localectl --help                                                                        #current LANG Settings
localectl list-locales
localectl set-locale LANG=en_US.UTF-8
vim /etc/locale.conf
LANG=fr_FR.utf8 date                                                             # set LANG for one command
yum langavailable
yum langlist
yum langinstall
################################################################################
#SSH
################################################################################
ssh-keygen
ssh-copy-id login@server.com
################################################################################
#Getting help RHEL
################################################################################
redhat-support-tool
redhat-support-tool search How to manage
redhat-support-tool kb 253273
redhat-support-tool analyze                                                      #ynalyze some file (from tomcat z.B)
redhat-support-tool listcases
redhat-support-tool opencase --product="Red Hat Enterprise Linux" -- version="7.0"
sosreport                                                                       #generate report for RH  (yum install sos)
kdump !TODO!

################################################################################
#FILE SYSTEM
################################################################################
# /usr - installed software,libraries,include files, static data
# /etc - configuration
# /var - variable data, that stay between reboots (db,cache,logs,website content)
# /run - runtime data for processes since last boot . On reboot are recreated (processID, locks, )
# /boot - files for booting
# /tmp - files are deleted in 10 days, /var/tmp - files are deleted in 30 days
man 7 hier                                                                      #description of all directories in Linux
ln -s file1 file2 file3 .                                                       #create in current directory 3 softlinks
################################################################################
su - root                                                                       # Sets $HOME, $PWD, and other variables from new user
su root                                                                         # Preserves $HOME, $PWD and some other variables


# IDS: 0=root, 1-200 system, 201-999 system, 1000+ regular
vim /etc/login.defs                                                             #chnage min/max uid,guid

#STICKY Bitmap (s -file, t -dir)
#rwsr-xr-x # command will run as owner of file
#drwxrwxrwxt # only owner of file can delete files in such directory
u+s = setuid
g+s = setguid
o+t = sticky
#UMASK
vim /etc/profile
vim /etc/bashrc
umask 002                                                                        #default 775
umask 007                                                                        #770
umask 027                                                                        #750
#ACCESS CONTROL LIST
#r-xr-xr-x+                                                                      # + at hte end means, that here is ACL
#files:
getfacl file.txt
setfacl -m u:mmeluzov:rX README.txt
setfacl -m g:mmeluzov:rX README.txt
setfacl -m o::- README
setfacl -m u:mmeluzov:r,g:mmeluzov:rwX,o::- README                              # all in one
setfacl -m m::r README                                                          # sets a mask, that limits all that exceeds mask
getfacl README | setfacl --set-file=- file1.txt                                 # use existing ACL from fileA to fileB
setfacl -x g:mmeluzov file1.txt                                                 # delete specific permission at ACL
setfacl -b file1.text                                                           # remove all ACL
#directory:
getfacl directory/
setfacl -R -m u::rwX directory/                                                 # recursive


getfacl -R directory/ >  acl.txt
setfacl --set-file=acl.txt

#######SELINUX##########
#MANUAL: *_selinux  (PACKAGE: selinux-policy-devel)
getenforce
getsebool
ls -Z
setenforce [1|0]
vim /etc/selinux/config
semanage fcontext
restorecon
chcon
setsebool
semanage boolean -l
sealert

###
authconfig                                                                      #cli
authconfig-gtk                                                                  #interactive cli
authconfig-tui                                                                  #graphical interface

!TODO! KERBEROS
!TODO! IPA  (ipa-client-install)
!TODO! realmd (realm )

#OTHER
pkexec --user root uptime                                                        # Analog of sudo
find / -nouser -o -nogroup 2> /dev/null                                          #find files without user or group

man bash
PS1="What next, master? "                                                       #change [mmeluzov@qcdb ~]$#
Ctrl+Alt+F1..F6

#Change virtual terminal in Graphical
################################################################################
############ PROCESS MANAGEMENT (p.161-)#############################
###K#ILLING
# pkill > killall > kill
pgrep -l -u bob                                                                  #list all processes for bob
kill -l                   # list of all signals, number can be different on differene systems
kill -signal PID
killall -signal somepattern
killall -u user -signal pattern
pkill -SIGKILL -u bob                                                           # (kill all processes from user bob)
pkill -SIGKILL -t tty3                                                          # (kill all processes from terminal tty3)
pkill -P 8391                                                                   # (kill all processes from parent process 8391)
pkill -e -15 sleep                                                              # kill all processes with sleep

#####LOGGING OUT
w
##### PTS- pseudoterminal, TTY -real terminal, JCPU -CPU resources for all tasks,including background  PCPU - foreground tasks
pkill -9 -t tty3
#####MONITORING PROCESS ACTIVIY
top
#####RENICING
#-20 ... 19 : Important ... unimportant
# Unprivilieged user cans set 0..19, root can -20..19
# Unprivileged users are not allowed to lower NICE value
nice -n 15 somecommand                      # defaul 10
renice -n 11 PID
top #(KEY "r" to renice )


################################################################################
############# UPDATING SOFTWARE PACKAGES (p.183-)#############################
##### RHEL Subscription MANAGEMENT
#RHEL: register system; subscribe system;
subscription-manager register --username=test --password=x
subscription-manager list --available
subscription-manager attach --auto
subscription-manager list --consumed
subscription-manager unregister
ll /etc/pki/product/    #contains certificates
ll /etc/pki/consumer/
ll /etc/pki/entitlement/
##### YUM
yum list
yum list 'mariadb*'
yum search 'mariadb'               # search by only in name and summary fileds
yum search all 'mariadb'               # search everythere
yum info mariadb-server
yum provides /var/lib/mysql/
yum update kernel
yum group list hidden ids
yum group list
yum group info mariadb-client
yum group install X
yum history
yum history undo N
yum history info N

yum repolist all
yum-config-manager --enable "rhui-REGION-rhel-server-supplementary/7Server/x86_64"
vim /etc/yum.repos.d/custom.repo  #add manual
yum-config-manager --add-repo  "http://repo.webtatic.com/yum/el7/x86_64/RPMS/"  #add with comand

################################################################################
###########CREATING AND MOUNTUNG FILE SYSTEMS (p.211) ##########################
#####MOUNTING
blkid
mount /dev/vdb1 /some/dir
mount  UUID="88fd4d41-c180-4721-80c6-535249a4a2bb" /dev/xvda2
lsof /some/dir          #find which process use mount point
umount
#PARTITIONING
#MBR (MAster-Boot-Record)vs GPT (Grand-Partition-Table)
#MBR: up to 15 partitions, max 2TiB
#GPT: up to 128 partitions, max 8ZiB, additional info for redudancy
fdisk /dev/sdx            #for MBR
partprobe /dev/sdx
gdisk                     # for GPT
#/etc/fstab format: DEVICE MOUNTPOINT TYPE OPTIONS DUMP_FLAG ORDER
####MANAGING SWAP
#1. Create partition 2. Set type 82 3. Format swap signature
#Add to /etfstab too
fdisk
mkswap
swapon /dev/sdb1
swapon -a
swapoff
################################################################################
########### SERVICE MANAGEMENT AND BOOT TROUBLESHOOTING (p.247) ################
systemctl      #print all
systemctl   type=[service|socket|path]   #print specific
systemctl is-active
systemctl is-enabled
systemctl --failed
systemctl list-unit-files --type=service
systemctl list-units --type=service
systemctl mask UNIT ## disable automatic and manuak start (by creating a softlink to /dev/null)

####BOOT PROCESS###
#The boot process on an x86 computer may be split into four major phases: the firmware phase, the boot loader phase, the kernel phase, and the initialization phase.
# FIRMWARE (BIOS/UEFI) -> Boot loader (grub2/uefi) -> kernel, initframs -> systemd
# FIRMWARE is is the BIOS or the UEFI code that is stored in flash memory on the x86 system board. POST (power-on-self-test) > scans storagedevies, finds boot device
# GRUB: searches kernel in /boot, loads kernel in memory based on config /boot/grub2/grub.cfg   (EFI: /boot/efi, /boot/efi/EFI/redhat/grub.efi )
# KERNEL: kernel loads initrd (initial RAM disk) image in memory and mounts as ro. Kernel loads modules, drivers. Them mount phisical root system  and unmount initrd
# SYSTEMD starts all enabled system and network services, and brings the system up to the preset boot target.

#F2 to enter BIOS Menu

# Repairing boot loadder issue
vim /boot/grub2/grub.CFG                # config, do not edit. Tool must be used
vim /etc/default/grub                   #confug file
vim /etc/grub.d/                        #config scripts
grub2-mkconfig  > /boot/grub2/grub.cfg  # Tool for generating config
grub2-mkconfig –o /boot/grub2/grub.cfg  #

grub2-set-default 1                     # Change default kernel. Kernels are numerated 0,1,2..N

systemctl poweroff           # = poweroff
systemctl reboot             # = reboot

#CHANGE TARGET
# ON BOOT: systemd.unit=rescue.target | systemd.unit=emergency.target
systemctl list-units --type=target                                              # list of all  targets
systemctl get-default
systemctl set-default multi-user.target                                         #
systemctl isolate multi-user.target                                             # switch to another target

### Restoring root password
#1) add rd.break 2) mount -o remount,rw /sysroot 3) chroot /sysroot 4) passwd  5)touch ./autorelabel 6)exit
#2) add init=/bin/sh -> mount -o remount,rw / -> passwd  -> touch ./autorelabel -> exec /sbin/init
#2) add afrer root partition rw init=/sysroot/bin/sh -> passwd  -> touch ./autorelabel -> exec /sbin/init
#3) systemctl enable debug-shell.service -> reboot -> press Ctrl+AltäF9, opens root terminal

#KERNEL
uname -r
#4.18.0-80.el8.x86_64
#4- major version
#18 - major revision
#0 - patch version
#80 - RH version
#el8 - Enterprise Linus 8
#x86_64 - architecture
#Kernel and its support files store in  /boot /proc /lib/modules
yum update kernel
yum list installed kernel

cat /proc/cmdline                                             #show parameter by last boot
cat /proc/version                                              #show parameter by boot

#KERNEL MODULEs
lsmod                                 #show modules
cat /proc/modules                 # = lsmod
modinfo tcp_diag

################################################################################
####################### Network Configuration (p.281) ##########################
ip a    #ip addr
ip addr show eth0    #ip addr
ip -s link show eth0      #show statustics
ip route    #show routing table
traceroute
tracepath some.site
cat /etc/services               #standart ports
ss -putan
#### Network MAnager  Text User Interface  (nmtui)
nmtui
#### Network manager (NMCLI)
#MANUAL  WITH EXAMPLES: man nmcli-examples
nmcli con show --active
nmcli con show  "NAME"  # show all info about conn
nmcli dev status
nmcli dev show "NAME"
nmcli con add con-name "default" type ethernet ifname eth0                       #add new DHCP connection
nmcli con add con-name "static" ifname autoconnect no type ethernet ip4 192.168.0.5/24 gw4 192.168.0.254 #add new static connection
nmcli con up "static"
nmcli con up "defalut"
nmcli con mod "default" connection.autoconnect no                                #Modify connection. Key-value

nmcli con mod "default" +ipv4.dns 8.8.8.8                                #Modify connection (add)
nmcli con mod "default" ipv4.dns 172.25.0.254                                #Mmodify dns nameserver
nmcli con mod "default" +ipv4.dns-search example2.com                       #add search  to dns
nmcli con del "default"                                #delete connection
nmcli net off #disable all managed interfaces
nmcli dev dis "default" #ebring down interface and disable autoconnect
nmcli con reload                                      #reread conf file from /etc/sysconfig/network-scripts
#ADD NEW CONNECTION <<<<
nmcli con show
nmcli con add con-name "static-eth0" ifname eth0 type ethernet ip4 172.31.31.100/20 gw4 172.31.16.1
nmcli con mod "static-eth0" ipv4.dns 172.31.0.2
nmcli con up  "static-eth0"
nmcli con mod "OLD ONE" connection.autoconnect no       #disable old
nmcli con show
#<<<<
#### Hostname, Name Resolution
hostname
hostnamectl status
hostnamectl set-hostname xxx
# ORDER: 1) /etc/hosts 2) /etc/resolv.conf
#/etc/resolv.conf :search - list of domain names to try with a short name, nameserver- ip adress of nameserver

################################################################################
#######################System Logging and NTP (p.307) ##########################
#systemd-journald: collects messages from kernel,boot. Does not persist between reboots
#rsyslogd:  uses messages from systemd-journald , sorts them and write to /var/log
#rsyslog Manual: /usr/share/doc/rsyslog-*/manual.html

vim /etc/rsyslog.conf
vim /etc/rsyslog.d/newrule.conf

logger -p user.debug "Test"                                                     #debug level
logger -p local7.notice "Log entry created"                                     #boot level

#journalctl
#/run/log/journal/
journalctl # show all entries in systemd log
journalctl -n 10 #show last 10
journalctl -p emerg #show only enries wit specific priority !!and above!! (debug-info-notice-warning-err-crti-alert-emerg)
journalctl -f                         # like tail -f shows last 10 and renews
journalctl --since YYYY-MM-DD hh:mm:ss                                          #Per default YYYY-MM-DD = today, hh:mm:ss = 00:00:00
journalctl --until today
journalctl -o verbose                           #Prints verbose, you can use those fileds to compolex searches
journalctl _SYSTEMD_UNIT=sshd.service _PID=12345        # fileds from verbose output
journalctl -b             #info since last boot
journalctl -b  -1 # info before previous reboot
#save journal log between reboots <<INPUT
mkdir -p /var/log/journal
chown root:systemd-journal /var/log/journal/
chmod 2755 /var/log/journal/
kill -USR1 1726 #systemd-journald id
#>>INPUT

timedatectl
timedatectl set-time 10:00:00                                         #set some time
timedatectl list-timezones                                        #list all TZ
tzselect  #interactive tool, helps to define TZ

#chrony
#chronyd
vim /etc/chrony.conf            # chronyd reads options from file
chronyc activity
chronyc ntpdata
chronyc -n sources -v
chronyc -n sourcestats -v
chronyc -n tracking


################################################################################
####################### Logical Volume Management (p.335) ######################
#/dev/vgname/lvname OR /dev/mapper/vg-name-lvname
#ADDING: PD-PV-VG-LV  |REMOVING: LV-VG-PV
## Add LV
#1. Prepare physical device
fdisk /dev/xda
partprobe   #after creating new partition
#2. Create phiscal volume
pvcreate /dev/vda2 /dev/vdb1
#3 Create volune group  (VG - pool of one or more PV)
vgcreate vg-somename /dev/vda2 /dev/vdb1
#4 Create logical volume
lvcreate -n lv-name -L 128G vg-name  2
#5. Add file system
mkfs -t xfs /dev/vg-name/lv-name
mkdir /mnt/somedir
vim /etc/fstab # add string: /dev/vg-name/lv-name /mnt/somedir xfs defaults 1 2
mount -a

## Remove LV
# Removing LV will destroy all data
#1. Prepare FS. Remove data to another FS,
umount /mnt/somedir
vim /etc/fstab # delete mount point from fstab
#2 Remove LV. #LV physical extents will be freed and made available for assigning to another LVs
lvremove /dev/vg-name/lv-name
#3. Remove VG. VGs phisical volumes will be freed and made available for assigment to existing or new VGs
vgremove vg-name
#4 Remove PV. After that you can to reforamt  or rellocate partition
pvremove /dev/vda2 /dev/vda1

## EXTEND
#1. Prepare physical device
fdisk /dev/xda
#2. Create phiscal volume
pvcreate /dev/vda2 /dev/vdb1
#3. Extend VG
vgextend  vg-name /dev/vdb1
#Verify
vgdisplay

## REDUCE
#1-Move data
pvmove /dev/vdb2   #Will move PEs from vdb2 to other PVs with free Pes in the same VG
#2. Reduce
vgreduce vg-name /dev/vdb2
#3 Delete PV
pvremove /dev/vdb2

## EXTEND LV and FS
vgdisplay vg-name  #1 Verify space is availabale
#2. Extend LV
lvextend  -L +300M /dev/vg-name/lv-name    # Add 300 MB
lvextend  -L 300M /dev/vg-name/lv-name     # Set 300MB
lvextend  -l +300 /dev/vg-name/lv-name     # Add 300 Extents  (!! small l)
lvextend  -l 300 /dev/vg-name/lv-name     # Set 300 Extents (!! small l)
lvextend  -l +50%FREE /dev/vg-name/lv-name     # Add 50% from current free space
#Extend FS
xfs_growfs /mnt/somedir                     # Expand FS  (xfs)
resize2fs /dev/vg-name/lv-name              # Expand FS (ext4)


#Review status
pvdisplay
vgdisplay
lvdisplay
################################################################################
####################### SCHEDULED PROCESSES (p.361) ############################
#CRONTAB
cat /etc/crontab      #Show diagram with help
/etc/cron.d/*

cat /etc/anacrontab
ll /var/spool/anacron/cron*       #If job runs, update timestamp of related file

run-parts
# crontab - e used for  users, /etc/crontab used for system-wide tasks
crontab -e      #crontab -e saves in
less /var/spool/cron/$USER

### managing temp files with systemd-tmpfiles
#Tool, used to clean up temporyr files (/tmp, /run/*,...)
man tmpfiles.d                                     #format and example for tmpfile.conf files
man systemd.timer
man systemd-tmpfiles


systemd-tmpfiles-setup  --create --remove    # runs on boot, read config file and clean and creates temp files , defined in files:
ll /etc/tmpfiles.d
ll /run/tmpfiles.d/
ll /usr/lib/tmpfiles.d/                       #Files here are provided form  vendors, do not edit them
#If youn nedd to edit , copy to /etc/tmpfiles.d/ and edit. This directory has higher priority


systemd-tmpfiles --clean             #Cleans temp file on timer. Timer is deined in [Timer block in service definition ]
systemd-tmpfiles --clean  somefile.conf         #run clean only for specific config file
env SYSTEMD_LOG_LEVEL=debug systemd-tmpfiles --clean tmp.conf       #DEBUGGING
stat /tmp/some.file                 #check atime, ctime,mtime


################################################################################
####################### Mounting NFS (p.373) ###################################
#Supported: NFSv4, NFSv3, NFSv2
#Supported secure methods: none, sys(default), krb5, krb5i, krb5p
#MANUAL:
man autofs, automount, auto.master, mount.nfs

#3 Way to mount NFS:
#1) usuall mount
#2) mount via /etc/fstab
#3) Automounting
yum install nfs-utils

#KERBEROS: for kerberos auth you nedd to have a file:
/etc/krb5.keytab
systemctl start  nfs-secure
systemctl enable nfs-secure

#STEPS TO MANUALLY MOUINT NFS SHARE:
#1 Identify
#NFSv2, NFSv3:
showmount -e serverX            #works only for NFSv3, NFSv2
#NFSv4: (mount root directory and then explore)
mkdir /somedir
mount serverX:/ /somedir
ls /somedir
#2 create mount point
mkdir /somedir
#3 Mount
mount -t nfs -o sec=sys,sync serverX:/remote/dir /somedir
vim /etc/fstab ; mount -a


#STEPS TO AUTO-MOUINT NFS SHARE:
#1 Create master config file *.autofs to /etc/auto.master.d/ , which idenifies base directory for mounts and  mapping file
#2 Create mapping file  (direct maps / indirect maps/ indirect maps using wildcards)
#3 enable and start  autofs

yum install autofs nfs-utils
echo "/shares /etc/auto.demo" >  /etc/auto.master.d/demo.autofs    #Example content
echo "work -rw,sync serverX:/path" > /etc/auto.demo    #Example content. It will mount /path to /shares/work
echo "* -rw,sync serverX:/shares/&" > /etc/auto.demo    #Example content. It will mount all subdirectories from share/
systemctl enable autofs
systemctl start autofs
##########################
##### Accessing Network Storage with SMB/CIFS
#SMB= Server MEssage Block  (protocol), CIFS = Common Internet File System (dialect) . Often says, that SMB=CIFS

yum install cifs-utils samba-client

###STEPS TO MANUALLY MOUINT SMB SHARE:
#1 Identify
smbclient -L //serverX  #list availables shares on serverX
#2 Determine mount point
mkdir -p /mountpoint
#3 Mount
mount -t cifs -o guest //serverX/share /mountpoint                # authenticate as guest
mount -t cifs -o username=user1 //serverX/share /mountpoint                # authenticate as user1, it will prompt password at mounting
mount -t cifs -o credentials=/secure/user1.sm //serverX/share /mountpoint                # authenticate as user1, password and login saved in /secure/user1.smb file
#Content of  /secure/user1 :
username=user1
password=xxx
domain=domain
##
chmod 600 /secure/user1

###STEPS TO AUTOMATICALLY MOUNT SMB SHARE
yum install autofs cifs-utils
echo "/xxx /etc/auto.demo" >  /etc/auto.master.d/demo.autofs    #Example content
echo "yyy -fstype=cifs,credentials=/secure/user1.smb ://serverX/yyy" > /etc/auto.demo    #Example content. It will mount /path to /shares/work
##ATTENTION on syntax  -fstype=cifs ://serverX/path
vim /secure/user1.smb
chmod 600 /secure/user1.smb

systemctl enable autofs
systemctl start autofs

################################################################################
####################### FIREWALL CONFIGURATION (p.409) #########################
################################################################################
#MANUAL
man firewall-cmd firewall-config firewalld firewalld.zone firewalld.zones
# netfilter is a poweful network filtering subsystem
netfilter
# iptables is old. Modern RHEL uses firewalld
iptables    #ipv4
ip6tables   #ipv6
ebtables    #bridges

for SERVICE in iptables ipt6tables ebtables; do systemctl mask ${SERVICE}.service ; done  #It is recommended to mask all *tables, to exclude conflicts

#firewalld  clssifies all traffic into zones. Each zone can habe its own rules and list of ports and services to be opened/closed
#1. If source address of packet matches source rule setup for zone , that packet will be routed to zone
#2. If incoming interface for a packet matches a filter setup for zone, that zone will be used
#3. Otherwise default zone is used

#NetworkManager can be used to automatically setup zones  for different connection (z.B work, home, public )
#Predefined zones:       trusted ,home,internal,work,public(def), external, dmz, block, drop
#Predefined services:     ssh(22), shcpv6-client(546), ipp-client(631), samba-client(137,138), mdns(5353)
firewall-cmd --get-services            #list all services
ll /usr/lib/firewalld/services/*         #config files for services

#3 Ways to interact with firewalld:
#1. Edit /etc/firewalld/
vim /etc/firewalld/...                    #In most cases, editing the config files is not reccomending, but it is useful to copy config
#2 Use GUI Version
yum install firewall-config
firewall-config
# Use CMD
firewall-cmd

###
# --timeout = <TIMEINSECONDS>       The rule will be canceled in X seconds
# --zone = <ZONE>                   Specific zone
# -- permanent                      #Save to permanent config.

firewall-cmd  --get-zones                          #list ALL zones
firewall-cmd  --get-active-zones                  # List all active zones
firewall-cmd  --get-default-zone                    #list default zone
firewall-cmd  --info-zone=ZONE -v                         # INFO ABout specific ZONE + verbose
firewall-cmd  --set-default-zone=ZONE

firewall-cmd  --list-all                           # Retrieve all information about default zone
firewall-cmd  --list-all-zones                     # Retrieve all information about all zones

#  With --permanent options a command saves changes to runtime&permanent config, otherwise saves only to runtime
firewall-cmd  --add-source=CIDR                   #ADD source-ip to default zone
firewall-cmd  --remove-source=CIDR                   # Remove source-ip from default zone

firewall-cmd  --add-interface=INTERFACE                   # Route all traffic from INTERFACE to default zone
firewall-cmd  --change-interface=INTERFACE                   # Associate INTERFACE with default zone

firewall-cmd  --info-service=ssh -v                      #In of about specific service
firewall-cmd  --add-service=SERVICE                   # Allow traffic to SERVICE
firewall-cmd  --remove-service=SERVICE                   # Disallow traffic to SERVICE

firewall-cmd  --add-port=PORT/PROTOCOL                   # Allow traffic to PORT/protocol
firewall-cmd  --add-port=5060-5065/udp                   # a range of ports
firewall-cmd  --remove-port=PORT/PROTOCOL                   # Disallow traffic to PORT/protocol
firewall-cmd  --add-source-port=8080/tcp                 # allow trafic from port

firewall-cmd --zone=external --add-masquerade   #willy masq. any packets sent to firewall from clients defined in sources
firewall-cmd --zone=external --query-masquerade
firewall-cmd --zone=external --remove-masquerade

#the packets intended for port 22 are now forwarded to the same port at the address given with the toaddr. The original destination port is specified with the port option.
firewall-cmd --zone=external --add-forward-port=port=22:proto=tcp:toport=3753:toaddr=192.168.2.2

firewall-cmd  --reload                                 #drop runtiome config and apply persistent

firewall-cmd  --query-panic
firewall-cmd  --panic-on                                 #drop all connections
firewall-cmd  --panic-off

#logging:
firewall-cmd --get-log-denied
firewall-cmd --set-log-denied=all

#EXAMPLE: Allow connections from 192.168.0.6/24 to mysql
firewall-cmd --set-default --zone=dmz
firewall-cmd --permanent --zone=internal --add-source=192.168.0.6/24
firewall-cmd --permanent --zone=internal --add-service=mysql
firewall-cmd --reload

#edit zone
ls /usr/lib/firewalld/zones/         # You can not edit files here  .
ls /etc/firewalld/zones/             # You can copy here and edit
cp /usr/lib/firewalld/zones/work.xml /etc/firewalld/zones/

####RICH RULES
man firewalld.richlanguage

# rule [family="rule family"]
#     [ source [NOT] [address="address"] [mac="mac-address"] [ipset="ipset"] ]
#     [ destination [NOT] address="address" ]
#     [ element ]
#     [ log [prefix="prefix text"] [level="log level"] [limit value="rate/duration"] ]
#     [ audit ]
#     [ action ]

firewall-cmd --list-rich-rule
firewall-cmd --query-rich-rule='<RULE>'
firewall-cmd --add-rich-rule='<RULE>'
firewall-cmd --remove-rich-rule='<RULE>'

firewall-cmd --permanent --zone=classroom --add-rich-rule='rule family=ipv4 source address=192.168.0.11/32 reject'      #reject all trafic ftpm ip in classroom zone
firewall-cmd --add-rich-rule='rule service name=ftp limit value=2/m accept'     #allow 2 new connections pro minute to ftp
firewall-cmd --add-rich-rule='rule protocol value=esp drop'  #REJECT send reply, DROP does nothing
firewall-cmd--permanent --zone=vnc --add-rich-rule='rulefamily=ipv4 source address=192.168.1.0/24 port port=7900-7905 protocol=tcp accept'
firewall-cmd --add-rich-rule='rule service name="ssh" log prefix="ssh " level="notice" limit value="3/m" accept'
firewall-cmd --add-rich-rule='rule family=ipv4 source address=192.168.0.0/24 masquerade'  #MASQUERADE  network
firewall-cmd --add-rich-rule='rule family=ipv4 source address=192.168.1.19/26 forward-port port=80 protocol=tcp to-port=8080'      #PORT-FORWARD















################################################################################
################# Virtualisation and Kickstart (p.423) #########################
################################################################################

###Kickstart
#Helps to automate installation. IT should be accessable during installation, z.B at Web-Server
/root/anaconda-ks.cfg
#Structure of anaconda
# %packages  - section with software to be installed
# %pre  - scripts executed BEFORE  any partiotioning done
# %post  -scripts executed AFTER  installation

#Different commands
url --url="ftp://some.url.com/pub/RHEL/8/dvd"
repo --name="Custom Package" --baseurl="ftp://some.url.com/custom"
text   #forces text mode install
vnc --password=redhat   #allows the installation to be viewed remotely via VNC
clearpart --all --drives=sda,sdb --initlabel  #clears specified partition before install
part /home --fstype=ext4 --label=home --size=4096 --myssize=8192 --grow # partition
ignoredisk --drives=sdc
bootloader --location=mbr --boot-drive=sda
#EXAMPLE how to create VG and LV <<START
part pv.01 --size=8192
volgroup myvg pv.01
logvol / --vgname=myvg --fstype=xfs --size=2048 --name=rootvol --grow
logvol /var --vgname=myvg --fstype=xfs --size=2048 --name=varvol
<<START
network --device=eth0 --bootproto=dhcp
firewall --enabled --service=ssh,cups
lang en_US.UTF-8
keyboard --vckeymap=us --xlayouts='us','us'
timezone --utc --ntpservers=time.example.com Europe/Berlin
auth --useshadow --enablemd5 --passalgo=sha512
rootpw --plaintext redhat
rootpw --iscrypted $6$dsdfsdfs.dfsdfsdfsdfdsfsdSDFAFasdfaSDFASDGadHNA
selinux --enforcing
services --disabled=network,iptables --enabled=firewalld,NetworkManager
group --name=admins --gid=1005
user --name=jdoe --group=admins --password=changeme --plaintext
# reboot,poweroff,halt   - commands after installation

ksverdiff    #utility to comapre syntax betwee different versions
ksverdiff -f RHEL6 -t RHEL7

#create ks file (GUI):
yum install system-config-kickstart
system-config-kickstart

yum install pykickstart
ksvalidator # checks syntax

#DOCUMENTATION
man ksvalidator system-config-kickstart
less /usr/share/doc/pykickstart-1.99.66.19/kickstart-docs.rst


#Option at booting from LiveCD ks=location/of/kickstartfile
ks=ftp://someserver.com/dir/file
ks=http://someserver.com/dir/file
ks=nfs:someserver.com:/dir/file
ks=hd:device:/dir/file
ks=cdrom:/dir/file



#Virtual Machine Manager
#KVM= Kernel-based Virtual Machine
#libvirt API
#Miminal requimnets: CPU:1, RAM:2GB+VM RAM, HDD: 6GB + 6GB*N
yum install qemu-kvm qemu-img                                                    # important packages
yum install virt-manager libvirt libvirt-python libvirt-client  python-virtinst  #additional packages

virt-manager         #GUI
virsh                #CLI
virsh list
virsh start server
virsh destroy server

#If something is not existing in KS file, it will be prompted


#--------------------------------------------


















































#SOLVING PROBLEMS
#Solving Network PROBlems
Ping google.com #check site
Ping 8.8.8.8 #check DNS
Ip route show
Ip route del default via 192.168.5.2
Ip route add default via 192.168.4.2
Ifdown eht0
Ifup eth0

#Solving Memory Problem
Emergency mode: systemd.unit=emergency.target
Mount -o remount,rw / # remount root in RW mode
Systemct start default.target

# SAVE KERNEL BOOT PARAMETER
vi /boot/grub2/grubenv ###  not sure this works
vim /etc/default/grub && grub2-mkconfig -o /boot/grub2/grub.cfg  # from anaconda
