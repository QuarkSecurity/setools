if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include share tests $(MAYBE_SWIG)

libapol.a libapol.so:
	$(MAKE) -C src $@
