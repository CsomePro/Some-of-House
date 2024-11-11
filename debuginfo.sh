#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

# 1. get debuginfo from debuginfod 
# 2. copy debuginfo file to /usr/lib/debug/.build-id/

# get file buildID
buildID=$(eu-readelf -n $1 | grep "Build ID" | awk '{print $3}')

# export DEBUGINFOD_URLS="https://debuginfod.elfutils.org/"
# download debuginfo file
debug_file=$(DEBUGINFOD_URLS="https://debuginfod.elfutils.org/" debuginfod-find debuginfo $buildID)

echo "debug_file: $debug_file"

build_id_prefix_2=${buildID:0:2}
build_id_suffix=${buildID:2}

target_file=/usr/lib/debug/.build-id/$build_id_prefix_2/$build_id_suffix.debug

echo "target_file: $target_file"

cp $debug_file $target_file
if [ $? -ne 0 ]; then
    read -p "Copy failed. Do you want to retry with sudo? (y/n): " answer
    if [ "$answer" = "y" ]; then
        sudo cp $debug_file $target_file
        sudo chmod 766 $target_file
    else
        echo "Operation aborted."
    fi
else
    chmod 766 $target_file
fi
