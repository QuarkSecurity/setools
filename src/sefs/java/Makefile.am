wrappedso_DATA = libjsefs.so.@libsefs_version@
wrappedso_SONAME = @libsefs_jswig_soname@
short_name = libjsefs.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.sefs
package_dir = $(dir $(subst .,/,$(package_name)))sefs

wrappedjar_DATA = sefs.jar
wrappedjardir = $(setoolsdir)

dist_noinst_DATA = $(srcdir)/../sefs.i
BUILT_SOURCES = sefs_wrap.cc \
	sefsConstants.java \
	sefs_db.java \
	sefs_entry.java \
	sefs_fcfile.java \
	sefs_fclist.java \
	sefs_fclist_type_e.java \
	sefs_filesystem.java \
	sefs.java \
	sefsJNI.java \
	sefs_query.java \
	SWIGTYPE_p_dev_t.java \
	SWIGTYPE_p_f_p_sefs_fclist_p_q_const__sefs_entry_p_void__int.java \
	SWIGTYPE_p_f_p_void_p_q_const__sefs_fclist_int_p_q_const__char_va_list__void.java \
	SWIGTYPE_p_ino64_t.java \
	SWIGTYPE_p_void.java

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ -fpic
AM_JFLAGS = @SETOOLS_JFLAGS@ \
	-classpath $(top_builddir)/src/qpol/java/qpol.jar:$(top_builddir)/src/apol/java/apol.jar
AM_LDFLAGS = @SETOOLS_LDFLAGS@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @SEFS_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libsefs.so

$(firstword $(BUILT_SOURCES)): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) -c++ $(SWIG_JAVA_OPT) -package $(package_name) -o $@ @SWIG_FLAGS@ $<

$(wordlist 2,$(words $(BUILT_SOURCES)), $(BUILT_SOURCES)): $(firstword $(BUILT_SOURCES))

$(wrappedso_DATA): $(filter %.cc, $(BUILT_SOURCES))
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_JAVA_CFLAGS) -DSWIGJAVA=1 $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

# Intentionally do not include SWIGTYPE_p_void.java below so that the
# Java compiler uses the one created in package
# com.tresys.setools.qpol instead of the one from package
# com.tresys.setools.sefs.
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
