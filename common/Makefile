#
# This file is part of trust|me
# Copyright(c) 2013 - 2018 Fraunhofer AISEC
# Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2 (GPL 2), as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
#


CC := musl-gcc
LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -I/usr/local/include -I/opt/cmldmusl/usr/include -pedantic -W
LOCAL_CFLAGS += -DDEBUG_BUILD
LDLIBS := -L/opt/cmldmusl/lib  -L/opt/cmldmusl/usr/lib -lc -lprotobuf-c -lprotobuf-c-text -lselinux -Lcommon -lcommon -lutil -lfts -lpcre


LOCAL_CFLAGS += -I../include -Wall -Wextra -std=gnu99 -D _POSIX_C_SOURCE=200809L -D _XOPEN_SOURCE=700 -D _DEFAULT_SOURCE

.PHONY: all
all: libcommon

libcommon: event list logf mem str nl
	ar rcs libcommon.a nl.o logf.o event.o list.o mem.o str.o

event: event.c event.h
	musl-gcc -c ${LOCAL_CFLAGS} event.c -o event.o

list: list.c list.h
	musl-gcc -c ${LOCAL_CFLAGS} list.c -o list.o

logf: logf.c logf.h
	musl-gcc -c ${LOCAL_CFLAGS} logf.c -o logf.o

mem: mem.c mem.h
	musl-gcc -c ${LOCAL_CFLAGS} mem.c -o mem.o

str: str.c str.h
	musl-gcc -c ${LOCAL_CFLAGS} str.c -o str.o

nl: nl.c nl.h
	musl-gcc -c ${LOCAL_CFLAGS} nl.c -o nl.o

sock: sock.c sock.h
	musl-gcc -c ${LOCAL_CFLAGS} sock.c -o sock.o
	

uuid: uuid.c uuid.h
	musl-gcc -c ${LOCAL_CFLAGS} uuid.c -o uuid.o


protobuf: logf.proto
	protoc-c --c_out=. logf.proto

.PHONY: clean
clean:
	rm -f *.o libcommon.a *.pb-c.*
