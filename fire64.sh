#!/bin/sh
gcc -DFIREALARM -c ws_comm.c  -Wall;ar crs libws_comm.a ws_comm.o;gcc -Wall -o test ./test.c  -L. -lws_comm  -lwolfssl -lcrypto -lpthread -lm
