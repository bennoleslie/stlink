CFILES = src/stlink-common.c src/stlink-flash.c src/stlink-usb.c src/uglylogging.c src/gdb-remote.c src/gdb-server.c
HEADERS = src/stlink-common.h src/stlink-flash.h src/stlink-usb.h src/uglylogging.h src/gdb-remote.h
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -O2
LDFLAGS = -lusb-1.0
OS_LDFLAGS =  -lobjc -Wl,-framework,IOKit -Wl,-framework,CoreFoundation

st-util: $(CFILES) $(HEADERS) Makefile
	gcc -I. -Isrc -L. $(CFILES) $(CFLAGS) -o $@ $(LDFLAGS) $(OS_LDFLAGS)

clean:
	rm st-util
