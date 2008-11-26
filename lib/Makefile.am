all: libqpol.so libapol.so libsefs.so libseaudit.so libpoldiff.so libpolsearch.so

libqpol.so:
	$(MAKE) -C $(top_srcdir)/src/qpol

libapol.so:
	$(MAKE) -C $(top_srcdir)/src/apol

libsefs.so:
	$(MAKE) -C $(top_srcdir)/src/sefs

libseaudit.so:
	$(MAKE) -C $(top_srcdir)/src/seaudit

libpoldiff.so:
	$(MAKE) -C $(top_srcdir)/src/poldiff

libpolsearch.so:
	$(MAKE) -C $(top_srcdir)/src/polsearch

mostlyclean-local:
	-rm -f lib*
