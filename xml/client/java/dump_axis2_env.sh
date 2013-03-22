#!/bin/sh

if test -z "${AXIS2_HOME}"; then
    exit 1
fi

. ${AXIS2_HOME}/bin/setenv.sh

echo "AXIS2_HOME=${AXIS2_HOME}"
echo "AXIS2_CLASSPATH=${AXIS2_CLASSPATH}"
exit 0

