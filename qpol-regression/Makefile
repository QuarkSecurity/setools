# regression tests 
MAKE 		= make
CC		= gcc

LIBSEPOL_PATH = ../../../../nsa-mainline/branch/setools_public-policydb-components/libsepol/

LIBSEPOL	= $(LIBSEPOL_PATH)src/libsepol.a

LIBSELINUX	= -lselinux

LIBS		= -lm -lfl $(LIBSELINUX)

OBJS		= $(LIBSEPOL) 

INCLUDES	= -I$(LIBSEPOL_PATH)include/

CFLAGS		+= $(INCLUDES)
CFLAGS 		+= -Wall -g3 -O3 -gdwarf-2 -Wshadow -Wmissing-prototypes \
	-Wstrict-prototypes -Wextra -Wnested-externs -Wundef -Wmissing-noreturn \
	-Wmissing-format-attribute

TESTS		 = qpol_booleans_test qpol_contexts_test qpol_class_perms_test qpol_genfscons_test \
		   qpol_netifcons_test qpol_nodecons_test

all : $(TESTS)

run : $(foreach test,$(TESTS),$(test).res)
	cat $^ > results/tests-$(DATE).results

%.res : %.o $(OBJS)
	@echo $* > $*.res0
	@./$* > $*.res1 2> $*.res2 
	@cat $*.res0 $*.res1 $*.res2 > $@ 
	@rm -f $*.res[012]

%.o : %.c
	$(CC) $(CFLAGS) -c $<

$(LIBSEPOL): libsepol 

libsepol:
	$(MAKE) DEBUG=1 -C $(LIBSEPOL_PATH)

test.o : test.c test.h
	$(CC) $(CFLAGS) -c $<


qpol_booleans_test: qpol_booleans_test.o qpol_test_lib.o test.o qpol_wrapper.h libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(LIBS) \
	qpol_test_lib.o test.o -o $@

qpol_contexts_test: qpol_contexts_test.o qpol_test_lib.o test.o qpol_wrapper.h libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(LIBS) \
	qpol_test_lib.o test.o -o $@

qpol_class_perms_test: qpol_class_perms_test.o qpol_test_lib.o test.o qpol_wrapper.h libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(LIBS) \
	qpol_test_lib.o test.o -o $@

qpol_genfscons_test: qpol_genfscons_test.o qpol_test_lib.o test.o qpol_wrapper.h libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(LIBS) \
	qpol_test_lib.o test.o -o $@

qpol_netifcons_test: qpol_netifcons_test.o qpol_test_lib.o test.o qpol_wrapper.h libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(LIBS) \
	qpol_test_lib.o test.o -o $@
qpol_nodecons_test: qpol_nodecons_test.o qpol_test_lib.o test.o qpol_wrapper.h libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(LIBS) \
	qpol_test_lib.o test.o -o $@

.PHONY : clean bare

clean : 
	rm -f *.o *.res $(TESTS) ./results/tests-*.results

bare : clean
	rm -f *~ core core.* a.out
