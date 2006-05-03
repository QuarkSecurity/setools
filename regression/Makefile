# regression tests 
MAKE 		= make
CC		= gcc

LIBSEPOL_PATH = ../../../../../nsa-mainline/branch/setools_public-policydb-components/libsepol
LIBAPOL_PATH    = ../../setools-libsepol/libapol

LIBSEPOL	= $(LIBSEPOL_PATH)/src/libsepol.a
#LIBAPOL		= ../../setools-libsepol/libapol/libapol.a

LIBSELINUX	= -lselinux

LIBS		= -lm -lfl $(LIBSELINUX)

OBJS		= test.o $(LIBAPOL) $(LIBSEPOL) 
OBJS		= test.o $(LIBSEPOL)

INCLUDES	= -I$(LIBSEPOL_PATH)/include/

CFLAGS		+= $(INCLUDES) -Wshadow -Wmissing-prototypes \
	-Wstrict-prototypes -Wextra -Wnested-externs -Wundef \
	-Wmissing-noreturn -Wmissing-format-attribute

ifeq ($(DEBUG), 1)
	CFLAGS += -g3 -gdwarf-2
else
	CFLAGS += -O2
endif


#TESTS		= partial_policy_loading component-query-test transitive_flow obj_perms perm_map_reload template reload roles binpol relabel role_rules subtract source_load memtest dta_test mls_query_test

TESTS		= $(QPOL_TESTS)

QPOL_TESTS	= qpol_booleans_test qpol_contexts_test qpol_class_perms_test \
		qpol_genfscons_test qpol_netifcons_test

DATE 		:= $(shell date +%Y%m%d%H%M)

all : $(TESTS)

run : $(foreach test,$(TESTS),$(test).res)
	cat $^ > results/tests-$(DATE).results

%.res : %.o $(OBJS)
	@echo $* > $*.res0
	@./$* > $*.res1 2> $*.res2 
	@cat $*.res0 $*.res1 $*.res2 > $@ 
	@rm -f $*.res[012]

test.o : test.c test.h
	$(CC) $(CFLAGS) -c $<

%.o : %.c
	$(CC) $(CFLAGS) -c $<

$(LIBAPOL): libapol

$(LIBSEPOL): libsepol 

libsepol:
	$(MAKE) DEBUG=1 -C $(LIBSEPOL_PATH)

libapol: 
	$(MAKE) DEBUG=1 -C $(LIBAPOL_PATH)/../ libapol


component-query-test : component-query-test.o test.o qpol-test-common.o libapol libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(LIBAPOL) $(CFLAGS) $(LIBS) test.o qpol-test-common.o -o $@

mls_query_test: mls_query_test.o test.o libapol libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(LIBAPOL) $(CFLAGS) $(LIBS) test.o -o $@

partial_policy_loading : partial_policy_loading.o test.o libapol libsepol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(LIBAPOL) $(CFLAGS) $(LIBS) test.o -o $@


transitive_flow : transitive_flow.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

obj_perms : obj_perms.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


perm_map_reload : perm_map_reload.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


template : template.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


reload : reload.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


roles : roles.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


binpol : binpol.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


relabel : relabel.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


role_rules : role_rules.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


subtract : subtract.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


source_load: source_load.o $(OBJS) $(LIBAPOL)
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


memtest: memtest.o $(OBJS) libapol
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@


dta_test : dta_test.o $(OBJS) libapol 
	$(CC) -L$(LIBSEPOL_PATH)src -lsepol -Wl,-rpath=$(LIBSEPOL_PATH)src $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

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

.PHONY : clean bare libapol

clean : 
	rm -f *.o *.res $(TESTS) ./results/tests-*.results

bare : clean
	rm -f *~ core core.* a.out
