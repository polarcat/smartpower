OUT = smartpower
SRC = smartpower.c

$(OUT):
	gcc $(SRC) -Wall -o $(OUT)

clean:
	-rm -f $(OUT)
