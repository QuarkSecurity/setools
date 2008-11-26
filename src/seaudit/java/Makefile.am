wrappedso_DATA = libjseaudit.so.@libseaudit_version@
wrappedso_SONAME = @libseaudit_jswig_soname@
short_name = libjseaudit.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.seaudit
package_dir = $(dir $(subst .,/,$(package_name)))seaudit

wrappedjar_DATA = seaudit.jar
wrappedjardir = $(setoolsdir)

dist_noinst_DATA = $(srcdir)/../seaudit.i
BUILT_SOURCES = seaudit_wrap.c \
	seaudit_avc_message_t.java \
	seaudit_avc_message_type_e.java \
	seaudit_bool_message_t.java \
	seaudit_filter_date_match_e.java \
	seaudit_filter_match_e.java \
	seaudit_filter_t.java \
	seaudit_filter_visible_e.java \
	seaudit.java \
	seauditJNI.java \
	seaudit_load_message_t.java \
	seaudit_log_t.java \
	seaudit_log_type_e.java \
	seaudit_message_t.java \
	seaudit_message_type_e.java \
	seaudit_model_t.java \
	seaudit_report_format_e.java \
	seaudit_report_t.java \
	seaudit_sort_t.java \
	tm_t.java \
	SWIGTYPE_p_void.java

AM_CFLAGS = @SETOOLS_CFLAGS@ -fpic
AM_JFLAGS = @SETOOLS_JFLAGS@ \
	-classpath $(top_builddir)/src/qpol/java/qpol.jar:$(top_builddir)/src/apol/java/apol.jar
AM_LDFLAGS = @SETOOLS_LDFLAGS@ @XML_LIBS@ \
	@SEAUDIT_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libseaudit.so

$(firstword $(BUILT_SOURCES)): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ @SWIG_FLAGS@ $<

$(wordlist 2,$(words $(BUILT_SOURCES)), $(BUILT_SOURCES)): $(firstword $(BUILT_SOURCES))

$(wrappedso_DATA): $(filter %.c, $(BUILT_SOURCES))
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_JAVA_CFLAGS) -DSWIGJAVA=1 $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

# Intentionally do not include SWIGTYPE_p_void.java below so that the
# Java compiler uses the one created in package
# com.tresys.setools.qpol instead of the one from package
# com.tresys.setools.seaudit.
java_files = $(filter-out SWIGTYPE_p_void.java, $(filter %.java, $(BUILT_SOURCES)))

classes = $(patsubst %.java, $(package_dir)/%.class, $(java_files))

# Because the Java compiler can generate multiple class files from the
# same source .java file, putting all of the classes below will result
# in repeated invocations of javac.  Therefore, an alternative is to
# just depend upon the first class file, and let the Java compiler
# create the rest of them.
$(firstword $(classes)): $(java_files)
	$(JAVAC) $(AM_JFLAGS) $(JAVAFLAGS) -d . $^

$(wordlist 2,$(words $(classes)),$(classes)): $(firstword $(classes))

$(wrappedjar_DATA): MANIFEST.MF

$(wrappedjar_DATA): $(classes)
	$(JAR) cfm $@ MANIFEST.MF $^

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(short_name)
	$(mkdir_p) $(DESTDIR)$(javadir) && cd $(DESTDIR)$(javadir) && $(LN_S) -f $(wrappedjardir)/$(wrappedjar_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/$(short_name)
	-rm -f $(DESTDIR)$(javadir)/$(wrappedjar_DATA)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(classes) $(wrappedso_DATA) $(wrappedjar_DATA) $(wrappedso_SONAME) $(short_name)
