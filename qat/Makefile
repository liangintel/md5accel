include $(PWD)/../../common.mk
OUTPUT_NAME=libqat_hash.so

EXTRA_CFLAGS += -fPIC -shared
EXTRA_CFLAGS += -Wl,-rpath,'$$ORIGIN/'

USER_SOURCE_FILES += qat_hash.c

test:test.c
	#gcc -o libqat_hash.so -fPIC -shared qat_hash.c
	$(RM) *.o test
	gcc -I${HOME}/incl -c test.c
	gcc -o test test.o -lqat_hash -L.

