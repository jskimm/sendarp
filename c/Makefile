all : arpspoof

arpspoof: main.o
	g++ -g -o arpspoof main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arpspoof
	rm -f *.o

