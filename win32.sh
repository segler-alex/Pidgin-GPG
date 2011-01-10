./configure --host i586-mingw32msvc
make clean
DIR=`pwd`
make LDFLAGS="-no-undefined -L$DIR/win32libs"
