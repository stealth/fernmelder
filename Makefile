CXX=c++
CFLAGS=-Wall -O2 -c -std=c++11 -pedantic

all: fernmelder

fernmelder: dns.o fm.o
	$(CXX) dns.o fm.o -lresolv -o fernmelder

dns.o: dns.cc dns.h
	$(CXX) $(CFLAGS) dns.cc

fm.o: fernmelder.cc
	$(CXX) $(CFLAGS) fernmelder.cc -o fm.o

clean:
	rm -rf *.o

