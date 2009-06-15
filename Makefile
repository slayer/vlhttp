
COPT=-DLIBLOG_ENABLED=1 -O -W -Wall -I liblog

linux:
	$(CC) $(COPT) -c -o log.o liblog/log.c
	$(CC) $(COPT) -c -o elhttp.o elhttp.c
	$(CC) $(COPT) -o elhttp log.o elhttp.o
	strip elhttp

sunos:
	gcc -O -W -Wall -o elhttp elhttp.c -lsocket -lnsl
	strip elhttp

unix:
	cc -O -o elhttp elhttp.c
	strip elhttp

