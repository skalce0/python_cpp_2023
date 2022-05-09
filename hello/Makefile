CPPFLAGS += -I /usr/include/python3.7
LIBS=`python3-config --ldflags`
#LIBS=-L/usr/lib/python3.7/config-3.7m-x86_64-linux-gnu -L/usr/lib -lpython3.7m -lcrypt -lpthread -ldl  -lutil -lm  -Xlinker -export-dynamic -Wl,-O1 -Wl,-Bsymbolic-functions 

COMPOSANT = hello_component

LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o

include ../gcc.mk
include ../pybind11.mk


all: $(LIBSO)
clean:
	rm -f ${LIBSO}  ${LIBSO_OBJS}


${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@

