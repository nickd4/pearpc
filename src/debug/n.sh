#!/bin/sh
gcc -DHAVE_CONFIG_H -I../.. -I.. -o ppcdis ppcdis.c ppcopc.c asm.c ../tools/debug.c ../tools/endianess.c ../tools/snprintf.c
