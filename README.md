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

