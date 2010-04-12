STRIP=strip
COPT=-O -W -Wall -I liblog -DLIBLOG_ENABLED -DLIBLOG_PIDCOLORS -g

linux:
	$(CC) $(COPT) -c -o log.o liblog/log.c
	$(CC) $(COPT) -c -o base64.o base64.c
	$(CC) $(COPT) -c -o vlhttp.o vlhttp.c
	$(CC) $(COPT) -o vlhttp log.o vlhttp.o base64.o
	$(STRIP) vlhttp

clean:
	-rm -f *.o vlhttp
