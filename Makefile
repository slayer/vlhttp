
COPT=-DLIBLOG_ENABLED=1 -O -W -Wall -I liblog

linux:
	$(CC) $(COPT) -c -o log.o liblog/log.c
	$(CC) $(COPT) -c -o vlhttp.o vlhttp.c
	$(CC) $(COPT) -o vlhttp log.o vlhttp.o
	strip vlhttp

sunos:
	gcc -O -W -Wall -o vlhttp vlhttp.c -lsocket -lnsl
	strip vlhttp

unix:
	cc -O -o vlhttp vlhttp.c
	strip vlhttp

