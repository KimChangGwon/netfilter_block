all : netfilter_block

netfilter_block: netfilter_block.o
	gcc -g -o netfilter_block netfilter_block.o -lnetfilter_queue

netfilter_block.o:
	gcc -g -c -o netfilter_block.o netfilter_block.c

clean:
	rm -f netfilter_block
	rm -f *.o

