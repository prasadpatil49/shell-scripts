#Checking the Storage Disk space
date1=`date +'%Y-%m-%d'`
OS=`uname -s`

if [ "${OS}" = "AIX" ] ; then
#AIX Server Storage space checking
echo "Hostname                                   : `hostname`" > /tmp/`hostname`_resources_details-$date1.csv
echo "IP Address                                 : `ifconfig -a | grep 172 | awk '{print $2}' | head -1`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Date                                       : `date`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total CPU (Entitled Capacity)              : `lparstat -i | egrep -w 'Entitled Capacity' |awk '{print $4,$5}' | grep -v Pool`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Memory                               : `lparstat -i | egrep -w 'Online Memory' |awk '{print $4,$5}'`" >> /tmp/`hostname`_resources_details-$date1.csv
#echo  "`lparstat -i | egrep -w 'Online Memory|Entitled Capacity' | grep -v Pool`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Paging Size                                : `lsps -s |awk '{print $1}' |tail -1`" >> /tmp/`hostname`_resources_details-$date1.csv
echo " " >> /tmp/`hostname`_resources_details-$date1.csv
echo "Storage Size " >> /tmp/`hostname`_resources_details-$date1.csv
echo "************  " >> /tmp/`hostname`_resources_details-$date1.csv
for i in `lspv | awk '{print $1}'`;do bootinfo -s $i;done | xargs > /tmp/data
disksize=`sed 's/ /+/g' /tmp/data | bc`
TOTAL=`expr $disksize / 1024`
#TOTAL=`echo "disksize" |awk '{print $1 / 1024}'`
df -gt | egrep -v ":" | awk '{print $2}' | egrep -v "GB|blocks|-" | xargs > /tmp/data1
fsallo=`sed 's/ /+/g' /tmp/data1 | bc `
df -gt | egrep -v ":" | awk '{print $3}' | egrep -v "GB|blocks|-" | xargs > /tmp/data2
fsused=`sed 's/ /+/g' /tmp/data2 | bc`
paging=`lsps -s | awk '{print $1}' | grep -v Total |cut -f1 -d"M"`
pagsize=`expr $paging / 1024`
lsvg -o|lsvg -i|grep -i "FREE PPs" |awk '{print $7}' |cut -f2 -d "(" | xargs > /tmp/data3
vgfree=`sed 's/ /+/g' /tmp/data3 | bc`
vgfree1=`expr $vgfree / 1024`
fsallo1=` echo "$fsallo" "$pagsize"|awk '{print $1 + $2}'`
fsused1=` echo "$fsused" "$pagsize"|awk '{print $1 + $2}'`
fsfree=` echo "$fsallo" "$fsused" |awk '{print $1 - $2}'`
echo "Total Allocated Disk(Storage) Size         : $TOTAL GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Size                      : $fsallo1 GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Used size                 : $fsused1 GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Free Size                 : $fsfree GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total VG Level Free Size                   : $vgfree1 GB" >> /tmp/`hostname`_resources_details-$date1.csv

elif [ "${OS}" = "Linux" ] ; then
#Linux server storage space checking
if [ -f /etc/redhat-release ] ; then
echo "Hostname                             : `hostname`" > /tmp/`hostname`_resources_details-$date1.csv
echo "IP Address                           : `ifconfig -a |egrep "172|128" | awk '{print $2}' | head -1 |cut -d ":" -f2`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "date                                 : `date`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total CPU                            : `cat /proc/cpuinfo |grep -i processor |wc -l`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Memory                         : `free -g |grep Mem |awk '{print $2}'` GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Swap Size                            : `free -g |grep Swap |awk '{print $2}'` GB" >> /tmp/`hostname`_resources_details-$date1.csv
swap=`free -g |grep Swap |awk '{print $2}'`
echo " " >> /tmp/`hostname`_resources_details-$date1.csv
echo "Storage Size"  >> /tmp/`hostname`_resources_details-$date1.csv
echo "************"  >> /tmp/`hostname`_resources_details-$date1.csv
fdisk -l |grep sd > /tmp/diskinfo.txt
grep -i bytes /tmp/diskinfo.txt |awk '{print $5}' | xargs > /tmp/diskinfo1.txt
disksize=`sed 's/ /+/g' /tmp/diskinfo1.txt | bc`
TOTAL=`expr $disksize / 1024`
TOTAL1=`expr $TOTAL / 1024`
TOTAL2=`expr $TOTAL1 / 1024`
df -mPl -x tmpfs -x devtmpfs | egrep -v ":" | awk '{print $2}' | egrep -v "GB|blocks|-|Size|Used" | xargs > /tmp/fileallo.txt
fileall=`sed 's/ /+/g' /tmp/fileallo.txt |bc`
filesalloc=`expr $fileall / 1000`

df -mP  -x tmpfs -x devtmpfs | egrep -v ":" | awk '{print $3}' | egrep -v "GB|blocks|-|Size|Used" | xargs > /tmp/fileused.txt
fileuse=`sed 's/ /+/g' /tmp/fileused.txt |bc`
filesused1=`expr $fileuse / 1000`

vgs --units m |awk '{print $7}' |grep -v VFree |cut -d "M" -f1 |cut -d "m" -f1 | xargs > /tmp/vglevefree.txt
vgfree=`sed 's/ /+/g' /tmp/vglevefree.txt |bc`
vgfreesize=`echo "$vgfree" |awk '{print $1 / 1024}'`

fsallocation=`echo "$filesalloc" "$swap" |awk '{print $1 + $2}'`
fsused=`echo "$filesused1" "$swap" |awk '{print $1 + $2}'`
fsfree0=`echo "$filesalloc" "$filesused1"|awk '{print $1 - $2}'`

echo "" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Allocated Disk(Storage) Size         : $TOTAL2 GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Size                      : $fsallocation GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Used Size                 : $fsused GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Free Size                 : $fsfree0 GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Free Size in VG Level                : $vgfreesize GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "output location : /tmp/`hostname`_resources_details-$date1.csv"

elif [ -f /etc/SuSE-release ] ; then
#checking suse Server checking
echo "Hostname                             : `hostname`" > /tmp/`hostname`_resources_details-$date1.csv
echo "IP Address                           : `ifconfig -a |egrep "172|128" | awk '{print $2}' | head -1 |cut -d ":" -f2`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "date                                 : `date`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total CPU                            : `cat /proc/cpuinfo |grep -i processor |wc -l`" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Memory                         : `free -g |grep Mem |awk '{print $2}'` GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Swap Size                            : `free -g |grep Swap |awk '{print $2}'` GB" >> /tmp/`hostname`_resources_details-$date1.csv
swap=`free -g |grep Swap |awk '{print $2}'`
echo " " >> /tmp/`hostname`_resources_details-$date1.csv
echo "Storage Size" >> /tmp/`hostname`_resources_details-$date1.csv
echo "************" >> /tmp/`hostname`_resources_details-$date1.csv
fdisk -l |grep sd > /tmp/diskinfo.txt
grep -i bytes /tmp/diskinfo.txt |awk '{print $5}' | xargs > /tmp/diskinfo1.txt
disksize=`sed 's/ /+/g' /tmp/diskinfo1.txt | bc`
TOTAL=`expr $disksize / 1024`
TOTAL1=`expr $TOTAL / 1024`
TOTAL2=`expr $TOTAL1 / 1024`
df -mPl -x tmpfs -x devtmpfs | egrep -v ":" | awk '{print $2}' | egrep -v "GB|blocks|-|Size|Used" | xargs > /tmp/fileallo.txt
fileall=`sed 's/ /+/g' /tmp/fileallo.txt |bc`
filesalloc=`expr $fileall / 1000`

df -mP  -x tmpfs -x devtmpfs | egrep -v ":" | awk '{print $3}' | egrep -v "GB|blocks|-|Size|Used" | xargs > /tmp/fileused.txt
fileuse=`sed 's/ /+/g' /tmp/fileused.txt |bc`
filesused1=`expr $fileuse / 1000`

vgs --units m |awk '{print $7}' |grep -v VFree |cut -d "m" -f1 |cut -d "m" -f1 | xargs > /tmp/vglevefree.txt
vgfree=`sed 's/ /+/g' /tmp/vglevefree.txt |bc`
vgfreesize=`echo "$vgfree" |awk '{print $1 / 1024}'`

fsallocation=`echo "$filesalloc" "$swap" |awk '{print $1 + $2}'`
fsused=`echo "$filesused1" "$swap" |awk '{print $1 + $2}'`
fsfree1=`echo "$filesalloc" "$filesused1" |awk '{print $1 - $2}'`

echo "" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Allocated Disk(Storage) Size         : $TOTAL2 GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Size                      : $fsallocation GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Used Size                 : $fsused GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Filesystem Free Size                 : $fsfree1 GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "Total Free Size in VG Level                : $vgfreesize GB" >> /tmp/`hostname`_resources_details-$date1.csv
echo "output location : /tmp/`hostname`_resources_details-$date1.csv"
chmod 775 "/tmp/`hostname`_resources_details-$date1.csv"
fi
fi

