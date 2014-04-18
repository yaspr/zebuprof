CPP=g++
CC=gcc
GCCPLUGINS_DIR=`$(CC) -print-file-name=plugin`
CFLAGS=-I$(GCCPLUGINS_DIR)/include -fPIC -O2

all : libzebu.so graph_plug.so 

graph_plug.so : graph_plug.c
	$(CPP) $(CFLAGS) -shared $^ -o $@

instru.so : instru.c
	$(CPP) $(CFLAGS) -shared $^ -o $@

pragma_inst_func.so : pragma_inst_func.c
	$(CPP) $(CFLAGS) -shared $^ -o $@

libzebu.so : zebu.c
	$(CC) -fPIC -shared $^ -o $@

test :
	LD_LIBRARY_PATH=. $(CPP) -O2 -pthread -fplugin=graph_plug.so func.c -L. -lzebu -o func

run_test :
	LD_LIBRARY_PATH=. ./func

clean :
	rm -f *~ *.so a.out *.dot func *.png *.mem
