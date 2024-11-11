#!/bin/bash

function usage() {
    echo "Usage: $0 [-v] <binary>"
    echo "Options:"
    echo "  -v: debuginfod-find verbose mode"
    exit 1
}

verbose=0
while getopts ":v" opt; do
    case ${opt} in
        v )
            verbose=1
            shift $((OPTIND -1))
            ;;
        \? )
            echo "Invalid option: -$OPTARG" 1>&2
            usage
            ;;
    esac
done

if [ $# -ne 1 ]; then
    usage
fi

binary=$1

# 1. get debuginfo from debuginfod 
# 2. copy debuginfo file to /usr/lib/debug/.build-id/

# get file buildID
buildID=$(eu-readelf -n $binary | grep "Build ID" | awk '{print $3}')

# export DEBUGINFOD_URLS="https://debuginfod.elfutils.org/"
# download debuginfo file
debug_flag=""
if [ $verbose -eq 1 ]; then
    debug_flag="-v"
fi

debug_file=$(DEBUGINFOD_URLS="https://debuginfod.elfutils.org/" debuginfod-find $debug_flag debuginfo $buildID)

if [ $? -ne 0 ]; then
    echo "Failed to get debuginfo file."
    exit 1
fi

if [ -z "$debug_file" ]; then
    echo "Failed to get debuginfo file."
    exit 1
fi

echo ""
echo -e "\e[32mSuccessfully get debuginfo file.\e[0m"
echo "Debug file: $debug_file"

build_id_prefix_2=${buildID:0:2}
build_id_suffix=${buildID:2}

target_file=/usr/lib/debug/.build-id/$build_id_prefix_2/$build_id_suffix.debug

echo "Copy to $target_file"

cp $debug_file $target_file
if [ $? -ne 0 ]; then
    read -p "Copy failed. Do you want to retry with sudo? (y/n): " answer
    if [ "$answer" = "y" ]; then
        sudo cp $debug_file $target_file
        sudo chmod 766 $target_file
    else
        echo "Operation aborted."
    fi
fi

# Check if the file permissions are 766, if not, change them
current_permissions=$(stat -c "%a" $target_file)
if [ "$current_permissions" -ne 766 ]; then
    # echo "Changing permissions of $target_file to 766"
    chmod 766 $target_file
fi

echo -e "\e[32mDone.\e[0m"