echo "" >  /tmp/`hostname`_artifacts.txt

date >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

hostname >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

ifconfig -a >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

ps -ef | grep pmon >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

ps -ef | grep sql >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

df -h >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

uptime >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

uname -a >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

cat /etc/fstab >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

netstat -rn >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

route -n >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

ntpq -p >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

chronyc sources >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

uname -r >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

df -h|wc -l >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

fdisk -l |grep -i sd >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

df -h|nl >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

 pvs >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

 vgs >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

 lvs >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

 free -m >> /tmp/`hostname`_artifacts.txt

echo -e "\n\n" >>  /tmp/`hostname`_artifacts.txt

 cat /proc/cpuinfo | grep -i proce >> /tmp/`hostname`_artifacts.txt 
