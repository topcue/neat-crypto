CC		= gcc
CFlAGS	= -W -Wall -o2

N = neat

all: $N

$N: $N.c
	@echo "##### [*] build neat"
	$(CC) $(CFLAGS) -o $@ $^

clean:
	@rm -rf *.o


# EOF

