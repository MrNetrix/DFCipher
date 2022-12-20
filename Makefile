TARGETS = dfcipher

CFLAGS = -g -funroll-loops -std=c99 -Wall -Wextra -pedantic -D_POSIX_C_SOURCE=199309L \
-I../libtomcrypt/src/headers
LDFLAGS = -lpthread -ltomcrypt \
-L../libtomcrypt

all : ${TARGETS}

dfcipher : dfcipher.o
	${CC} $^ -o $@ ${CFLAGS} ${LDFLAGS}

%.o : %.c
	${CC} $^ -c -o $@ ${CFLAGS}

clean :
	rm -f ${TARGETS}
	rm -f *.o
	rm -f *~
