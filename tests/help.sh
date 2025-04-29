#!/bin/sh

echo "$1 --help"
"$1" --help 2>&1

echo "$1 -h"
"$1" -h 2>&1
