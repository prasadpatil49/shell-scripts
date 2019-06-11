ls /etc/passwd_3_sep_2017_`hostname` 

if [ $? -eq 0 ]
then
echo "File already Present"
else
echo "Taking Backup"

cp -p /etc/passwd /etc/passwd_3_sep_2017_`hostname`
fi





for i in `grep -i Machhindra /etc/passwd | grep -i thange | awk -F: '{print $1}'`
do
usermod -c "1205923/TCS/DCH/Prasad Patil/System/Mgr157271" $i
done
