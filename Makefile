CFLAGS 		= -Wall -Wextra -O2 -s
PROGRAM 	= zkill
INSTALLPATH 	= /usr/local/bin

all:
	${CC} ${CFLAGS} ${PROGRAM}.c -o ${PROGRAM}

install:
	cp ${PROGRAM} ${INSTALLPATH}

clean:
	@rm -f ${PROGRAM}
