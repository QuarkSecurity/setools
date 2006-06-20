# regression tests 
MAKE 		= make
CC		= gcc

LIBQPOL_PATH	= ../../setools-libsepol/libqpol
LIBSEPOL_PATH  	= /home/aferucci/nsa-mainline/libsepol

LIBQPOL		= -L$(LIBQPOL_PATH)/src -Wl,-rpath=$(LIBQPOL_PATH)/src
LIBSEPOL	= -L$(LIBSEPOL_PATH)/src -Wl,-rpath=$(LIBSEPOL_PATH)/src

LIBSELINUX	= -lselinux -lsepol

LIBS		= -lm -lfl $(LIBSELINUX) -lqpol

INCLUDES	= -I$(LIBQPOL_PATH)/include -I$(LIBSEPOL_PATH)/include

CFLAGS		+= $(INCLUDES) $(LIBQPOL)
CFLAGS 		+= -Wall -g3 -O3 -gdwarf-2 -Wshadow -Wmissing-prototypes \
		-Wstrict-prototypes -Wextra -Wnested-externs -Wundef -Wmissing-noreturn \
		-Wmissing-format-attribute

LDFLAGS =	$(LIBQPOL) $(LIBSEPOL)

TESTS		 = qpol_types_test qpol_booleans_test qpol_class_perms_test qpol_genfscons_test \
		   qpol_netifcons_test qpol_nodecons_test qpol_mls_test

TESTS-RES = $(foreach test,$(TESTS),$(test).res)
OBJS = $(foreach test,$(TESTS),$(test).o)

DATE := $(shell date +%Y%m%d%H%M)

all : $(TESTS)

help:
	@echo "Interesting make targets for tests"
	@echo "	    all 	- build all tests"
	@echo "	    run-tests 	- run all regression tests"


run-tests:
	make all
	$(foreach test, $(TESTS), ./$(test))

run : $(TESTS-RES)
	mkdir -p results
	cat $^ > results/tests$(DATE).results

%.res : %.o $(OBJS) $(TESTS)
	@echo $* > $*.res0
	@./$* > $*.res1 2> $*.res2 ; if [ $$? -ne 0 ]; then echo "$* failed."; fi
	@cat $*.res0 $*.res1 $*.res2 > $@ 
	@rm -f $*.res[012]

%.o : %.c
	$(CC) $(CFLAGS) -c $<

test.o : test.c test.h
	$(CC) $(CFLAGS) -c $<

qpol_booleans_test: qpol_booleans_test.o qpol_test_lib.o test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS) 

qpol_class_perms_test: qpol_class_perms_test.o qpol_test_lib.o test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

qpol_genfscons_test: qpol_genfscons_test.o qpol_test_lib.o test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

qpol_netifcons_test: qpol_netifcons_test.o qpol_test_lib.o test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

qpol_nodecons_test: qpol_nodecons_test.o qpol_test_lib.o test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

qpol_types_test: qpol_types_test.o qpol_test_lib.o test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

qpol_mls_test: qpol_mls_test.o test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)


clean : 
	rm -f *.o *.res $(TESTS) ./results/tests-*.results

bare : clean
	rm -f *~ core core.* a.out

.PHONY : clean bare

$(OBJS): qpol_wrapper.h
