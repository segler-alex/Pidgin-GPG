# pidgin-gpg

## Building

```
apt-get install libpurple-dev libgpgme11-dev
autoreconf -i
./configure
make
mkdir -p ~/.purple/plugins
cp src/.libs/pidgin_gpg.so ~/.purple/plugins/
```

## Usage

Select Tools > Plugins, and enable the GPG/OpenGPG plugin. Select
configure and choose your GPG key.

gpg-agent needs to be enabled for this plugin to work properly. You
may need to restart pidgin to be prompted for the key passphrase after
enabling this plugin.

## About

This is not the official branch. I'm maintaining this fork simply for
maintenance (the original branch did not build with recent version of
autoreconf). I'm *am not* actively developing pidgin-gpg, mainly making
sure it keeps working and building. Releases > 0.9 should not be confused
with those of the original author (though the original author seems to
have stopped all development).
