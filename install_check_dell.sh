#!/bin/bash
#
# Author:   Ryan Bowlby <ryan.bowlby @ hostway>
#
# Purpose:  Install python Nagios plugin for checking Dell hardware (check_dell).
#           Not everyone is rocking puppet awesomeness. :(
#

URL_subprocess='http://cvs.lysator.liu.se/viewcvs/viewcvs.cgi/root.tar.gz?root=python-popen5'
URL_check_dell='http://www.ryanbowlby.com/check_dell.txt'

function install_subprocess() {
   # Python devel files installed?
   if [ ! -e $(python -c 'from distutils.sysconfig import get_makefile_filename as m; print m()') ]; then
      echo "Error: Please install the python-devel package for your distro and re-run." >&2
      exit 1
   fi
   cd /usr/src
   wget -O - $URL_subprocess 2> /dev/null | tar xzf - && cd python-popen5/popen5
   if ! python setup.py install > /dev/null 2>&1; then
      echo "Error: unable to install subprocess module."
   fi
}

# Verify Python is installed and set SHEBANG.
if ! PYTHON=`which python`; then
   echo "Error: Python is not in PATH, correct PATH or install Python." >&2
   exit 1
fi

# Verify subprocess module exists or install it.
if ! $PYTHON -c "import subprocess" > /dev/null 2>&1; then
   if `$PYTHON -V 2>&1 | cut -d'.' -f2` -gt 2; then
      echo -n 'Error: Python subprocess module not installed. Attempt install? (Y/n)'
      read ans
      if [ $ans == "n" -o $ans == "N" ]; then
         echo "Exiting.." && exit
      else
         install_subprocess
      fi
   else
      echo 'Error: Current version of Python not supported (2.3 or higher only).' >&2
      exit 1
   fi
fi

# Add omreport symlink to /usr/sbin.
if OMREPORT=`which omreport`; then
   ln -s $OMREPORT /usr/sbin/ > /dev/null 2>&1
else
   echo "Error: omreport is not in PATH, correct PATH or install OMSA." >&2
   exit 1
fi

# Determine Nagios plugins directory.
if [ -d /usr/lib/nagios/plugins/ ]; then
   PLUGINSDIR="/usr/lib/nagios/plugins/"
elif [ -d /usr/lib64/nagios/plugins/ ]; then
   PLUGINSDIR="/usr/lib/nagios/plugins/"
else
   echo "Error: unable to determine Nagios plugins directory."
   echo -n "Please specify plugins directory:"
   read PLUGINSDIR
   if [ ! -d $PLUGINSDIR ]; then
      echo "Error: specified dir does not exist. Exiting.." >&2 && exit 1
   fi
fi

# Download plugin.
if ! wget -O ${PLUGINSDIR}/check_dell.py $URL_check_dell >/dev/null 2>&1; then
   echo "Error: Unable to download plugin from: $URL_check_dell" >&2
   exit 1
fi

# Modify plugin shebang.
sed -i "1s|^.*$|#!${PYTHON}|" ${PLUGINSDIR}/check_dell.py

# Backup previous plugin version.
if [ -e $PLUGINSDIR/check_dell ]; then
   cp ${PLUGINSDIR}/check_dell ${PLUGINSDIR}/check_dell.old_version
fi

mv ${PLUGINSDIR}/check_dell.py ${PLUGINSDIR}/check_dell
chmod u+x ${PLUGINSDIR}/check_dell
exit 0
