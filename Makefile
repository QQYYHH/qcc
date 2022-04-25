OBJS= main.o lex.o string.o
qcc: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	rm -f qcc *.o tmp.*