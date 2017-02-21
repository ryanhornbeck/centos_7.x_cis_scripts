#!/bin/sh
# CIS Hardening Script for CentOS 7.x LTS v0.1

# Set http and https proxies for TCH
# echo export http_proxy="http://ladczproxy.am.thmulti.com:80" >> /etc/profile
# echo export https_proxy="https://ladczproxy.am.thmulti.com:80" >> /etc/profile
#  /etc/profile

set -e

yum -y install epel-release &&
yum -y install chrony ntp syslog-ng rsyslog unzip curl git aide &&
# yum -y install chage python-novaclient python-keystoneclient figlet
yum -y remove telnet &&
yum -y remove openssh-server &&

chmod 744 /usr/sbin/aide &&
# aide --init &&
# mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
# crontab -u root -e
cat scripts/crontab.file >> /usr/sbin/aide  &&

# Reformat disks
# placeholder for /etc/fstab and filesystem changes

# mount -o remount,nosuid /dev/shm
# mount -o remount,noexec /dev/shm

# mount -o remount,nodev /tmp
# mount -o remount,nodev /var/tmp

# df --local -P | awk if (NR!=1) print $6 | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2&gt;/dev/null | xargs chmod a+t

# chown root:root /boot/grub/grub.conf
# chmod og-rwx /boot/grub/grub.conf

# grub-md5-crypt
# Password: &lt;password&gt;
# Retype Password: &lt;password&gt;
# &lt;encrypted-password&gt;

# cat scripts/grub.d_00_header.file >> /etc/grub.d/00_header
# update-grub

# Edit /etc/sysconfig/init and set SINGLE to ' /sbin/sulogin ':
# SINGLE=/sbin/sulogin

# Edit the /etc/sysconfig/init file and set PROMPT to ' no ':
# PROMPT=no

# Add the following line to the /etc/security/limits.conf file or a /etc/security/limits.d/* file:
# * hard core 0
# Set the following parameter in the /etc/sysctl.conf file:
# fs.suid_dumpable = 0
# Run the following command to set the active kernel parameter:
# sysctl -w fs.suid_dumpable=0

# Set the following parameter in the /etc/sysctl.conf file:
# kernel.randomize_va_space = 2
# Run the following command to set the active kernel parameter:
# sysctl -w kernel.randomize_va_space=2

yum -y install prelink
prelink -ua
yum -y remove prelink

echo "Welcome to Technicolor." >> /etc/motd

cp /etc/issue /etc/issue.orig
cat scripts/banner.file >> /etc/issue

echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue.net

cp /etc/issue.net /etc/issue.net.orig
cat scripts/issues_net.file >> /etc/issue.net 

chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

# Banner /etc/issue.net

# Create the /etc/dconf/profile/gdm file with the following contents:
# user-db:user
# system-db:gdm
# file-db:/usr/share/gdm/greeter-dconf-defaults
# Create or edit the banner-message-enable and banner-message-text options in /etc/dconf/db/gdm.d/01-banner-message :
# [org/gnome/login-screen]
# banner-message-enable=true
# banner-message-text='Authorized uses only. All activity may be monitored and reported.'
# Run the following command to update the system databases:
# dconf update

# chkconfig chargen-dgram off
# chkconfig chargen-stream off
# chkconfig daytime-dgram off
# chkconfig daytime-stream off
# chkconfig discard-dgram off
# chkconfig discard-stream off
# chkconfig echo-dgram off
# chkconfig echo-stream off
# chkconfig time-dgram off
# chkconfig time-stream off
# chkconfig rexec off
# chkconfig rlogin off
# chkconfig rsh off
# chkconfig talk off
# chkconfig telnet off
# chkconfig tftp off
# chkconfig rsync off
# chkconfig xinetd off

mv /etc/ntp.conf /etc/ntp.conf.orig
cat scripts/ntp.file > /etc/ntp.conf

# Add or edit restrict lines in /etc/ntp.conf to match the following:
# restrict -4 default kod nomodify notrap nopeer noquery
# restrict -6 default kod nomodify notrap nopeer noquery
# Add or edit server lines to /etc/ntp.conf as appropriate:
# server &lt;remote-server&gt;
# Add or edit the OPTIONS in /etc/sysconfig/ntpd to include ' -u ntp:ntp ':
# OPTIONS=&amp;quot;-u ntp:ntp&amp;quot;

# Add or edit server lines to /etc/chrony.conf as appropriate
# server &lt;remote-server&gt;
# Add or edit the OPTIONS in /etc/sysconfig/chronyd to include ' -u chrony ':
# OPTIONS=&amp;quot;-u chrony&amp;quot;

# chkconfig avahi-daemon off
# chkconfig cups off
# chkconfig dhcpd off
# chkconfig slapd off
# chkconfig nfs off
# chkconfig rpcbind off
# chkconfig named off
# chkconfig vsftpd off
# chkconfig httpd off
# chkconfig dovecot off
# chkconfig smb off
# chkconfig squid off
# chkconfig snmpd off
# chkconfig ypserv off

# yum -y install ntpd
chkconfig nptd on &&
/etc/init.d/nptd stop &&
ntpdate pool.ntp.org &&
/etc/init.d/ntpd start 

yum -y remove xorg-x11* ypbind rsh talk telnet openldap-clients

# Set the following parameter in the /etc/sysctl.conf file:
# net.ipv4.ip_forward = 0
# Run the following commands to set the active kernel parameters:
# sysctl -w net.ipv4.ip_forward=0
# sysctl -w net.ipv4.route.flush=1

# Edit /etc/postfix/main.cf and add the following line to the RECEIVING MAIL section. If the line already exists, change it to look like the line below:
# inet_interfaces = localhost
# Restart postfix:
# service postfix restart

# Set the following parameters in the /etc/sysctl.conf file:
# net.ipv4.conf.all.send_redirects = 0
# net.ipv4.conf.default.send_redirects = 0
# net.ipv4.conf.all.accept_source_route = 0
# net.ipv4.conf.default.accept_source_route = 0
# net.ipv4.conf.all.accept_source_route = 0
# net.ipv4.conf.default.accept_source_route = 0
# net.ipv4.conf.all.accept_redirects = 0
# net.ipv4.conf.default.accept_redirects = 0
# net.ipv4.conf.all.secure_redirects = 0
# net.ipv4.conf.default.secure_redirects = 0
# net.ipv4.conf.all.log_martians = 1
# net.ipv4.conf.default.log_martians = 1
# net.ipv4.icmp_echo_ignore_broadcasts = 1
# net.ipv4.icmp_ignore_bogus_error_responses = 1
# net.ipv4.conf.all.rp_filter = 1
# net.ipv4.conf.default.rp_filter = 1
# net.ipv4.tcp_syncookies = 1

# net.ipv6.conf.all.accept_ra = 0
# net.ipv6.conf.default.accept_ra = 0
# net.ipv6.conf.all.accept_redirects = 0
# net.ipv6.conf.default.accept_redirects = 0

# Run the following commands to set the active kernel parameters:
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1

yum -y install tcp_wrappers

# echo &amp;quot;ALL: &lt;net&gt;/&lt;mask&gt;, &lt;net&gt;/&lt;mask&gt;, ...&amp;quot; &gt;/etc/hosts.allow
# echo &amp;quot;ALL: ALL&amp;quot; &gt;&gt; /etc/hosts.deny

chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

yum -y install iptables
chmod a+x iptables_sec.sh
sh iptables_sec.sh

service auditd reload
chkconfig rsyslog on

# Edit the /etc/rsyslog.conf and set $FileCreateMode to 0640 or more restrictive:
# $FileCreateMode 0640

# Edit the /etc/rsyslog.conf file and add the following line (where loghost.example.com is the name of your central log host).
# *.* @@loghost.example.com
# Run the following command to restart rsyslog :
# pkill -HUP rsyslogd

chkconfig syslog-ng off
# Edit the /etc/syslog-ng/syslog-ng.conf and set perm option to 0640 or more restrictive:
# options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };

yum -y install rsyslog
yum -y install syslog-ng

find /var/log -type f -exec chmod g-wx,o-rwx {} +

chkconfig crond on
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# rm /etc/cron.deny
# rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

yum -y install openssh-server
chkconfig sshd on

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# Protocol 2
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# LogLevel INFO
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# LogLevel INFO
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# MaxAuthTries 4
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# IgnoreRhosts yes
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# HostbasedAuthentication no
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# PermitRootLogin no
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# PermitEmptyPasswords no
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# PermitUserEnvironment no
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# Ciphers aes256-ctr,aes192-ctr,aes128-ctr
# Edit the /etc/ssh/sshd_config file to set the parameter in accordance with site policy. The following includes all supported and accepted MACs:
# MACs hmac-sha2-512,hmac-sha2-256
# Edit the /etc/ssh/sshd_config file to set the parameters as follows:
# ClientAliveInterval 300
# ClientAliveCountMax 0
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# LoginGraceTime 60
# Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:
# AllowUsers &lt;userlist&gt;
# AllowGroups &lt;grouplist&gt;
# DenyUsers &lt;userlist&gt;
# DenyGroups &lt;grouplist&gt;

# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the appropriate options for pam_cracklib.so and to conform to site policy:
# password requisite pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files and add the following pam_faillock.so lines surrounding a pam_unix.so line modify the pam_unix.so is [success=1 default=bad] as listed in both:
# auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
# auth [success=1 default=bad] pam_unix.so
# auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
# auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the remember option and conform to site policy as shown:
# password sufficient pam_unix.so remember=5
# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the sha512 option for pam_unix.so as shown:
# password sufficient pam_unix.so sha512

# Set the PASS_MAX_DAYS parameter to 90 in /etc/login.defs :
# PASS_MAX_DAYS 90
# Modify user parameters for all users with a password set to match:
# chage --maxdays 90 &lt;user&gt;
# PASS_MIN_DAYS 7
# Modify user parameters for all users with a password set to match:
# chage --mindays 7 &lt;user&gt;
# PASS_WARN_AGE 7
# Modify user parameters for all users with a password set to match:
# chage --warndays 7 &lt;user&gt;
# Run the following command to set the default password inactivity period to 30 days:
# useradd -D -f 30
# Modify user parameters for all users with a password set to match:
# chage --inactive 30 &lt;user&gt;

# chmod a+x scripts/nologin.sh
# sh scripts/nologin.sh

usermod -g 0 root

# Edit the /etc/bashrc and /etc/profile files (and the appropriate files for any other shell supported on your system) and add or edit any umask parameters as follows:
# umask 027

# Add the following line to the /etc/pam.d/su file:
# auth required pam_wheel.so use_uid
# Create a comma separated list of users in the wheel statement in the /etc/group file:
# wheel:x:10:root,&lt;user list&gt;

chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:root /etc/shadow
chmod 000 /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
chown root:root /etc/shadow-
chmod 600 /etc/shadow-
chown root:root /etc/group-
chmod 600 /etc/group-
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-

# sh scripts/world_writable_files.sh
# sh scripts/world/world_writable_dirs_sticky.sh

# Cleanup

