check_dell
==========

Plugin to Nagios and Zabbix to parse OMSA (Dell OpenManage Server Administrator) 

About OMSA 
==========
OMSA (http://en.wikipedia.org/wiki/OpenManage) provides a CLI interface to check system integrity.

You can install OMSA on Windows, Ubuntu server or Centos/RedHat Linux.

Repositories can be found at:
CentOS/RedHat: http://linux.dell.com/wiki/index.php/Repository/OMSA
Ubuntu/Debian: http://linux.dell.com/repo/community/deb/


Zabbix Usage
==========

Call check_dell with -n option. It will return number of errors. You can use zabbix.conf UserParameter:
    UserParameter=dell.storage,check_dell -s -n
    UserParameter=dell.chassis,check_dell -c all -n

