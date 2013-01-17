check_dell
==========

Plugin to Nagios and Zabbix to parse OMSA (Dell OpenManage Server Administrator) 

About OMSA 
==========
OMSA (http://en.wikipedia.org/wiki/OpenManage) provides a CLI interface to check system integrity.

You can install OMSA on Windows, Ubuntu server or Centos/RedHat Linux.


Repositories can be found at:

- CentOS/RedHat: http://linux.dell.com/wiki/index.php/Repository/OMSA

- Ubuntu/Debian: http://linux.dell.com/repo/community/deb/

Installing on Ubuntu
===========

echo 'deb http://linux.dell.com/repo/community/deb/latest /' > /etc/apt/sources.list.d/linux.dell.com.sources.list

apt-get update

apt-get install srvadmin-all git

ln -s /opt/dell/srvadmin/bin/omreport /usr/sbin/omreport

cd /opt

git clone https://github.com/Desenvolve/check_dell.git

install -m 0755 /opt/check_dell/check_dell /usr/sbin

# testing

check_dell -s 

check_dell -c all

# testing error counters

check_dell -s -n

check_dell -c all -n



Zabbix Usage
==========

Call check_dell with -n option. It will return number of errors. You can use zabbix.conf UserParameter:

UserParameter=dell.storage,check_dell -s -n

UserParameter=dell.chassis,check_dell -c all -n


Credits 
==========
Parser script was write by Ryan Bowlby and published at http://ryanbowlby.com/2009/12/27/omreport-nagios-check_dell/


