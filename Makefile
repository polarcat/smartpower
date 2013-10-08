OUT = smartpower
SRC = smartpower.c

$(OUT): $(SRC)
	gcc $< -Wall -O2 -o $@

clean:
	-rm -f $(OUT)

$(OUT): Makefile
