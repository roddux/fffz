#!/bin/sh	
# forget trying to do this in a Makefile
mkdir gen || true
(
    echo -n "uintptr_t _restore_offsets_function_address = 0x";
    readelf --dyn-syms bin/imposer.so |\
    awk '/restore_offsets/{print $2}'|\
    tr '\n' ';';
    echo;
) > gen/imposer_offset_header.h
