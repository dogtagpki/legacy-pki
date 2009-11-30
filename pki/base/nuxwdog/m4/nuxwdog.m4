dnl BEGIN COPYRIGHT BLOCK
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl 
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl 
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin Street, Fifth Floor,
dnl Boston, MA  02110-1301  USA 
dnl 
dnl Copyright (C) 2007 Red Hat, Inc.
dnl All rights reserved.
dnl END COPYRIGHT BLOCK

AC_CHECKING(for pre-built Ant PKIDOG JNI Headers and Jars)

# check for --with-pkidog
AC_MSG_CHECKING(for --with-pkidog)
AC_ARG_WITH(pkidog, [  --with-pkidog=PATH        PKIDOG directory],
[
  if test -f "$withval"/include/com_redhat_pkidog_WatchdogClient.h -a -f "$withval"/jars/pkidog.jar
  then
    AC_MSG_RESULT([using $withval])
    PKIDOGDIR=$withval
    pkidog_inc="-I$PKIDOGDIR/include"
    pkidog_jars="$PKIDOGDIR/jars/pkidog.jar"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-pkidog-inc
AC_MSG_CHECKING(for --with-pkidog-inc)
AC_ARG_WITH(pkidog-inc, [  --with-pkidog-inc=PATH        PKIDOG (Generated JNI Headers) include file directory],
[
  if test -f "$withval"/com_redhat_pkidog_WatchdogClient.h
  then
    AC_MSG_RESULT([using $withval])
    pkidog_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-pkidog-jars
AC_MSG_CHECKING(for --with-pkidog-jars)
AC_ARG_WITH(pkidog-jars, [  --with-pkidog-jars=PATH        PKIDOG (Jars) jars directory],
[
  if test -f "$withval"/pkidog.jar
  then
    AC_MSG_RESULT([using $withval])
    pkidog_jars="$withval/pkidog.jar"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-jni-inc (insure use of appropriate jni.h)
AC_MSG_CHECKING(for --with-jni-inc)
AC_ARG_WITH(jni-inc, [  --with-jni-inc=PATH        PKIDOG jni.h header path],
[
  if test -f "$withval"/jni.h
  then
    AC_MSG_RESULT([using $withval])
    jni_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[case $host in
  *-*-linux*)
    javac_exe=`/usr/sbin/alternatives --display javac | grep link | cut -c27-`
    jni_path=`dirname $javac_exe`/../include
    jni_inc="-I$jni_path -I$jni_path/linux"
    if test -f "$jni_path"/jni.h
    then
      AC_MSG_RESULT([using $jni_inc])
    else
      echo
      AC_MSG_ERROR([$jni_inc not found])
    fi
    ;;
  sparc-sun-solaris*)
    jni_path="/usr/java/include"
    jni_inc="-I$jni_path -I$jni_path/solaris"
    if test -f "$jni_path"/jni.h
    then
      AC_MSG_RESULT([using $jni_inc])
    else
      echo
      AC_MSG_ERROR([$jni_inc not found])
    fi
    ;;
  *)
    AC_MSG_ERROR([unconfigured platform $host])
    ;;
esac])

# check for PKIDOG generated headers and jar file in well-known locations
AC_MSG_CHECKING(for pkidog JNI headers and jars in well-known locations)
if test -z "$pkidog_inc" -o -z "$pkidog_jars"
then
  if test -f $srcdir/build/include/com_redhat_pkidog_WatchdogClient.h
  then
    pkidog_inc="-I$srcdir/build/include"
  else
    echo
    AC_MSG_ERROR([use Ant to create $srcdir/build/include/com_redhat_pkidog_WatchdogClient.h first])
  fi
  if test -f $srcdir/build/jars/pkidog.jar
  then
    pkidog_jars="$srcdir/build/jars/pkidog.jar"
  else
    echo
    AC_MSG_ERROR([use Ant to create $srcdir/build/jars/pkidog.jar first])
  fi
  if test -d $srcdir/build/include -a -f $pkidog_jars
  then
    AC_MSG_RESULT([using pre-built Ant pkidog JNI generated headers and Jar file])
  else
    AC_MSG_RESULT(no)
  fi
else
  AC_MSG_RESULT(no)
fi

# if pkidog Java portions have not been found, print an error and exit
if test -z "$pkidog_inc"
then
  echo
  AC_MSG_ERROR([PKIDOG generated JNI headers include file directory not found, specify with --with-pkidog.])
fi
if test -z "$pkidog_jars"
then
  echo
  AC_MSG_ERROR([PKIDOG jars directory not found, specify with --with-pkidog.])
fi
