if [ "$(uname)" == "Linux" ]
then

echo -e "User ID  Last Login Date\n\n" | cat > /tmp/`hostname`_last_login_details.txt

for i in `cat /etc/passwd | awk -F: '{print $1}'`
do

if [ -n "$(lastlog -u $i | grep -i never)" ]
then
echo "$i  Never Logged In" >> /tmp/`hostname`_last_login_details.txt
else
echo "$i  `lastlog -u $i | tail -n 1 | awk '{print $5" "$6" "$9}'`" >> /tmp/`hostname`_last_login_details.txt
fi

done

fi

if [ "$(uname)" == "AIX" ]
then
echo "User ID  Last Login Date\n\n" | cat > /tmp/`hostname`_last_login_details.txt

for i in `cat /etc/passwd | awk -F: '{print $1}'`
do
lastlog=$(lsuser $i | awk -F"time_last_login=" '{print $2}' | awk '{print $1}')
if [ -n "$(lsuser $i | grep time_last_login)" ]
then
echo "$i  $(echo "\c"; perl -le "print scalar localtime($lastlog);")" >> /tmp/`hostname`_last_login_details.txt

else
echo "$i  Never Logged In " >> /tmp/`hostname`_last_login_details.txt
fi
done

fi