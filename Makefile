CFLAGS=-g
OBJS=lex.o string.o util.o parser.o gen.o list.o

$(OBJS) unittest.o main.o: qcc.h

qcc: qcc.h main.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ main.o $(OBJS)

unittest: qcc.h unittest.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ unittest.o $(OBJS)

test: unittest
	./unittest
	./mytest.sh

clean:
	rm -f qcc *.o tmp.* unittest