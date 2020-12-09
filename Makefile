all: airodump

airodump: main.cpp main.h
	gcc -o airodump main.cpp -lpcap -std=c++0x

clean:
	rm -f airodump *.o

