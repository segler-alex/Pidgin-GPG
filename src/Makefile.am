plugin_LTLIBRARIES = pidgin_gpg.la

plugindir = ${libdir}/pidgin

pidgin_gpg_la_SOURCES = pidgin-gpg.c
pidgin_gpg_la_CFLAGS = $(PIDGIN_CFLAGS) $(PURPLE_CFLAGS) $(GPGME_CFLAGS)
pidgin_gpg_la_LDFLAGS = -module -avoid-version $(PIDGIN_LIBS) $(PURPLE_LIBS) $(GPGME_LIBS)
