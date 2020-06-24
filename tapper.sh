#!/bin/bash
# Create dnstap socket and read results
# 
# Start before nsd
# logs in UTC, not current time, so -2h

SOCKET="/var/log/nsd/nsd-dnstap.sock"
DNSTAP_LOG="/var/log/nsd/nsd-dnstap.log.%Y%m%d-%H"
TAPPER_LOG="/var/log/nsd/tapper.log"

function check_args() {
    if [ $# -eq 0 ]
    then
        echo "usage: $0 [stdout | write] &" >&2
        exit
    fi
}

function kill_running() {
    pids=$(ps aux | grep 'dnstap' | sed '$ d' | awk '{print $2}')
    for pid in $pids; do
        kill -9 $pid
    done
    echo -e "Killed:\n$pids\n" >&2
}

function read_socket() {
    if [ "$1" = "stdout" ];then
        su -m nsd -c "dnstap -u $SOCKET -j 2> $TAPPER_LOG"
    elif [ "$1" = "write" ];then
        # ensure there is always a tap
        while test 1; do
            su -m nsd -c "dnstap -u $SOCKET -j 2> $TAPPER_LOG | rotatelogs $DNSTAP_LOG 3600"
        done
    else
        echo "$1 not recognized."
        exit
    fi
}

function independent() {
    trap "" 1
}

function main() {
    check_args "$@"
    kill_running
    independent
    read_socket "$@"
}

main "$@"
