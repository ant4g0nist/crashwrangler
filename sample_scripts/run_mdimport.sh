#!/bin/sh -x

export CW_CURRENT_CASE=$1
export CW_USE_GMAL=1

./exc_handler mdimport "$1"

