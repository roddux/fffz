#!/bin/sh	
# forget trying to do this in a Makefile
mkdir gen || true
(
    echo -n "uinptr_t offset = 0x";
    readelf --dyn-syms bin/imposer.so |\
    awk '/restore_offsets/{print $2}'|\
    tr '\n' ';';
    echo;
) > gen/imposer_offset_header.h
