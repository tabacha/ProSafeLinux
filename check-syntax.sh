#!/bin/bash
DOCSTRING=C0111
FIXME=W0511
UNUSED_ARG=W0613
EXCEPTION_TYPE=W0702
INSTANCE_ATTRIBUTE=R0902
METHOD_FUNCTION=R0201
ABSTRACT=W0223
LOG=/tmp/psl_check_syntax.log

if [ -f $LOG ] ; then
    echo Logfile $LOG exists, please remove first
    exit 1
fi

pylint -d $DOCSTRING  -d $FIXME -d $UNUSED_ARG -d $EXCEPTION_TYPE \
       -d $INSTANCE_ATTRIBUTE  -d $METHOD_FUNCTION \
       -d $ABSTRACT psl_typ.py >$LOG 2>&1

T=$?

if [ "$T" != "0" ] ; then
    cat $LOG
fi

pylint -d $DOCSTRING  -d $FIXME -d $UNUSED_ARG -d $EXCEPTION_TYPE \
       -d $INSTANCE_ATTRIBUTE psl.py >$LOG 2>&1

M=$?
if [ "$M" != "0" ] ; then
    cat $LOG
fi

rm $LOG
if [ "$M" == "0" -a "$T" == "0" ] ; then
    echo Okay
fi