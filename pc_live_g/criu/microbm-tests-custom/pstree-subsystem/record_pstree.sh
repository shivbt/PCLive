#!/bin/bash

EXEC_NAME='pstree'

while true
do
    echo "{"
    ps axjf | grep $EXEC_NAME
    echo "}"
    echo ""
    sleep 1
done
