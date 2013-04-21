pidgin-gpg
==========

Building
--------
    autoreconf -i
    ./configure
    make
    cp src/.libs/pidgin_gpg.so ~/.purple/plugins/

Usage
-----
Select Tools > Plugins, and enable the GPG/OpenGPG plugin. Select
configure and choose your GPG key.

gpg-agent needs to be enabled for this plugin to work properly. You
may need to restart pidgin to be prompted for the key passphrase after
enabling this plugin.

About
-----
This is not the official branch. I'm maintianing this fork simply for
maintenence (the original branch did no build with recent version of
autoreconf). I'm *am not* actively developing pidgin-gpg, maintly making
sure it keeps working and building. Releases > 0.9 should not be confused
with those of the original author (though the original author seems to
have stopped all development).
