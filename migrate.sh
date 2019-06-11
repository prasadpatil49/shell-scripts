echo "\n" | cat > /tmp/`hostname`_migrationdetails.txt
chmod 777 /tmp/`hostname`_migrationdetails.txt
echo "Host Name:- `hostname`\n" >>/tmp/`hostname`_migrationdetails.txt
echo "---------------------------------------------" >>/tmp/`hostname`_migrationdetails.txt

if which pcmpath > /dev/null 2>&1
then
vfc=`pcmpath query wwpn| wc -l` 

vfc=$(($vfc - 1))
echo "\nTotal Number of VFC Adapter :-$vfc\n" >>/tmp/`hostname`_migrationdetails.txt
pcmpath query wwpn >>/tmp/`hostname`_migrationdetails.txt

else

echo "\nTotal Number of VFC Adapter :-`lscfg -vpl fcs* | grep Net| wc -l`\n" >>/tmp/`hostname`_migrationdetails.txt

#lscfg -vpl fcs* | grep fcs  | awk '{print $1}'
lscfg -vpl fcs* | grep Net | awk -F. '{print $14}' >>/tmp/`hostname`_migrationdetails.txt


fi



echo "\n---------------------------------------------" >>/tmp/`hostname`_migrationdetails.txt
echo "|    PV Name |        SerialNo |       Size |" >>/tmp/`hostname`_migrationdetails.txt
echo "---------------------------------------------" >>/tmp/`hostname`_migrationdetails.txt
for i in `lsdev -Cc disk | grep IBM | awk '{print $1}'`
do

#echo "$i     `lscfg -vpl $i | grep -i serial | awk -F. '{print $16}'`        `bootinfo -s $i` "
printf "| %10s | %15s | %10s |\n" $i $(lscfg -vpl $i | grep -i serial | awk -F. '{print $16}') $(bootinfo -s $i) >>/tmp/`hostname`_migrationdetails.txt



done

echo "---------------------------------------------" >>/tmp/`hostname`_migrationdetails.txt

echo "Total Disk Count:- `lsdev -Cc disk | grep IBM | wc -l`" >>/tmp/`hostname`_migrationdetails.txt

echo "---------------------------------------------" >>/tmp/`hostname`_migrationdetails.txt




echo "\nBoot Disk:-\n" >>/tmp/`hostname`_migrationdetails.txt


for i in `lspv | grep -w rootvg  | awk '{print $1}'`
do

#echo "$i     `lscfg -vpl $i | grep -i serial | awku -F. '{print $16}'`        `bootinfo -s $i` "

printf "| %10s | %15s | %10s |\n" $i $(lscfg -vpl $i | grep -i serial | awk -F. '{print $16}') $(bootinfo -s $i) >>/tmp/`hostname`_migrationdetails.txt

done

