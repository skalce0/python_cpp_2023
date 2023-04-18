CPPFLAGS += `python3-config --includes`
LIBS=`python3-config --ldflags`

COMPOSANT = hello_component

LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o

all: test $(LIBSO)

include ../gcc.mk
include ../pybind11.mk


test: $(LIBSO)
	echo "execution du test"
	python3 test.py

clean:
	rm -f ${LIBSO}  ${LIBSO_OBJS}


${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@

