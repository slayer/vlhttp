
linux:
	$(CC) -O -W -Wall -c -I liblog -o log.o liblog/log.c
	$(CC) -O -W -Wall -o elhttp log.o elhttp.c
	strip elhttp

sunos:
	gcc -O -W -Wall -o elhttp elhttp.c -lsocket -lnsl
	strip elhttp

unix:
	cc -O -o elhttp elhttp.c
	strip elhttp

