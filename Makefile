
#COPT=-DLIBLOG_ENABLED=1 -O -W -Wall -I liblog
COPT=-O -W -Wall -I liblog -DLIBLOG_ENABLED -DLIBLOG_PIDCOLORS

linux:
	$(CC) $(COPT) -c -o log.o liblog/log.c
	$(CC) $(COPT) -c -o base64.o base64.c
	$(CC) $(COPT) -c -o vlhttp.o vlhttp.c
	$(CC) $(COPT) -o vlhttp log.o vlhttp.o base64.o
	#strip vlhttp

sunos:
	gcc -O -W -Wall -o vlhttp vlhttp.c -lsocket -lnsl
	strip vlhttp

unix:
	cc -O -o vlhttp vlhttp.c
	strip vlhttp

