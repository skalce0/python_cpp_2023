CPPFLAGS += `python3-config --includes`
LIBS=`python3-config --ldflags`

COMPOSANT = my_component

LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o uECC.o

all: test $(LIBSO)

include ../gcc.mk
include ../pybind11.mk

uECC.o: ./micro-ecc/uECC.c
	g++ -c -o $@ $< $(CPPFLAGS)

test: $(LIBSO)
	echo "execution du test"
	python3 test.py
	
clean:
	rm -f ${LIBSO} ${LIBSO_OBJS}

${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@
