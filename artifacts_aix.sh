echo "" > /tmp/`hostname`_artifacts.txt

hostname >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt

lspv >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt
 

lspv | wc -l >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


lsvg >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


lsvg | wc -l >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


oslevel -s >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


ifconfig -a >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt

 
netstat -nr >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


df -gt >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt

 
df -gt | wc -l >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


bootlist -m normal -o >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt

 
lparstat -i >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


ps -eaf | grep -v root >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


lsdev -Cc disk >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


lsdev -Cc adapter >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


prtconf >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt

 
uptime >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


bootinfo -b >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


lsvg -o | lsvg -il >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


lssrc -s sendmail >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


lssrc -ls xntpd >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


ntpdate -d 172.31.9.241 >> /tmp/`hostname`_artifacts.txt

echo "\n\n" >> /tmp/`hostname`_artifacts.txt


