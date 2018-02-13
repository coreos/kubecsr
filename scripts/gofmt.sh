#!/bin/bash -e

result=$( go fmt $@ )
if [[ $result != "" ]]; then
    >&2 echo "The following files are not formatted correctly: $result"
    exit 1
fi