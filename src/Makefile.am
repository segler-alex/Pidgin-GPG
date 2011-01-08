plugin_LTLIBRARIES = pidgin_gpg.la

plugindir = ${libdir}/pidgin

pidgin_gpg_la_SOURCES = pidgin-gpg.c
pidgin_gpg_la_CFLAGS = $(PURPLE_CFLAGS) $(GPGME_CFLAGS) -I/usr/include
pidgin_gpg_la_LDFLAGS = -module -avoid-version $(PURPLE_LIBS) $(GPGME_LIBS)
