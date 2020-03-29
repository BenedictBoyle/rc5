#Makefile for toy rc5 program
CC = gcc
CFLAGS = -g -Wall 
LDFLAGS = -g -Wall 
RM=rm -f
LIBS = -lm

SRCS=primitives.c crypt.c ioroutines.c main.c
OBJS=$(subst .c,.o,$(SRCS))
all: rc5

rc5: $(OBJS)
	$(CC) $(LDFLAGS) -o rc5 $(OBJS) $(LIBS)

main.o: main.c ioroutines.c crypt.c

crypt.o: crypt.c primitives.c

ioroutines.o: ioroutines.c crypt.c

primitives.o: primitives.c 

clean: 
	$(RM) $(OBJS)
