./configure --host i586-mingw32msvc
make clean
make LDFLAGS="-no-undefined -L/mnt/data/segler/pidgin-gpg/Pidgin-GPG/win32libs/"
