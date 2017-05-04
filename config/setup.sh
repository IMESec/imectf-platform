#!/bin/bash

# Warn the user about running this on their host machine
# (because it makes various invasive settings-changes, and runs a ton of vulnerable services)
echo -e "\x1b[31;1mDON'T RUN THIS ON YOUR REAL COMPUTER\x1b[0m"
echo "Are you running this inside a VM? (If you don't know what that means, don't run the script.)"
read -p "(yes/no)> "
if [ "$REPLY" != 'yes' ]; then
  exit
fi

if [ "$USER" != 'root' ]; then
  echo "ERROR: Script must be run using root!"
  exit
fi

pushd ..

# update system
apt-get update
apt-get -y upgrade
apt install shellinabox python-dev python-pip sqlite3
pip install --upgrade pip
pip install virtualenv
. env/bin/activate
pip install -r requirements.txt

# restricting access mostly means make root accessible only, chmod 700 or s/t
chmod 700 `which dmesg`
chmod 700 `which fuser`
#chmod 700 `which htop`
chmod 700 `which kill`
chmod 700 `which killall`
chmod 700 `which lsof`
chmod 700 `which pgrep`
chmod 700 `which pkill`
chmod 700 `which ps`
chmod 700 `which screen`
chmod 700 `which su`
chmod 700 `which tmux`
chmod 700 `which top`
#chmod 700 `which ulimit`
chmod 700 `which users`
chmod 700 `which w`
chmod 700 `which wall`
chmod 700 `which who`
chmod 700 `which write`

# restrict access to /proc/maps/
sed -i 's/^exit 0$//' /etc/rc.local
echo -e 'mount -o remount,hidepid=2 /proc\n' >> /etc/rc.local
mount -o remount,hidepid=2 /proc
chmod 551 /proc

# isolate users
mount -o remount,hidepid=2 /proc
chmod 1733 /tmp /var/tmp /dev/shm
chmod -R o-r /var/log /var/crash
chmod o-w /proc

chmod 1111 /home/

# disable ssh'ing ? (not sure if possible, but these make it harder)
iptables -A OUTPUT -p tcp --dport 22 -j DROP
chmod 700 `which ssh`

# disable aslr
echo 0 | tee /proc/sys/kernel/randomize_va_space
echo 'kernel.randomize_va_space = 0' > /etc/sysctl.d/01-disable-aslr.conf

# disable crontab
touch /etc/cron.allow

popd

# copy security config files
ln -s limits.conf /etc/security/limits.conf
ln -s sysctl.conf /etc/sysctl.conf
ln -s imectf.conf /etc/init/imectf.conf
ln -s nginx /etc/nginx/sites-available/ctf.imesec.org
ln -s nginx /etc/nginx/sites-enabled/ctf.imesec.org

# This needs to be here
echo 'exit 0' >> /etc/rc.local

echo '*** DONE! ***'
echo -n 'reboot now? (y/n): '
read REBOOT
if [ "$REBOOT" == 'y' ]; then
    reboot
else
    echo 'You must reboot for certain settings to kick in'
    echo 'Please reboot soon'
fi
