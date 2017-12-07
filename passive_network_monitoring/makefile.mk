mydump: mydump.c
	gcc -g mydump.c -lpcap -o mydump

clean:
	rm -f mydump
