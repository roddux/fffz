#!/bin/sh	
# forget trying to do this in a Makefile
mkdir gen &>/dev/null || true

# incl
echo "#include <stdint.h>" > gen/imposer_offset_header.h

# restore_offsets
(
    echo -n "uintptr_t _restore_offsets_function_address = 0x";
    readelf --dyn-syms bin/imposer.so |\
    awk '/restore_offsets/{print $2}'|\
    tr '\n' ';';
    echo;
) >> gen/imposer_offset_header.h

# restore_heap_size
(
    echo -n "uintptr_t _restore_heap_size_function_address = 0x";
    readelf --dyn-syms bin/imposer.so |\
    awk '/restore_heap_size/{print $2}'|\
    tr '\n' ';';
    echo;
) >> gen/imposer_offset_header.h

# TODO: this probably isn't portable whatsoever
(
    echo -n "uintptr_t _base_address_offset = "; # readelf provides 0x for the header
    readelf --wide -l bin/imposer.so |\
    awk '/R.E/{print $2}'|\
    tr '\n' ';';
    echo;
) >> gen/imposer_offset_header.h
