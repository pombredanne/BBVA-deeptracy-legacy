#!/usr/bin/env bash

COUNTER=0
SECONDS=0

while [  $COUNTER -lt 1 ]; do
    # do some work
 duration=$SECONDS
 echo -ne "$(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed.\r"
 sleep 10
 SECONDS=$(($SECONDS + 10))
 COUNTER=$(docker ps -a -f name=patton-init | grep Exit | wc -l )
done

echo "Patton loaded successfully\n"

