TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += debug_and_release


INCLUDEPATH	+= /usr/local/include/
INCLUDEPATH	+=./
INCLUDEPATH	+=../../
INCLUDEPATH	+= ../AVProto/

SOURCES += \
	DH-example.c \
    utility_routines.c \
    gost89.c \
    ../AVProto/avproto.c



LIBS		+= -Wl,-Bstatic -ldl
LIBS		+= -L/usr/local/lib/ -lssl -lcrypto
LIBS		+= -Wl,-Bdynamic -ldl -pthread



CONFIG (debug, debug|release) {
	CONFIG	+= warn_off
	DEFINES	+= _DEBUG=1 __TRACE__=1

} else {
	CONFIG	+= warn_off
	DEFINES	+= _DEBUG=1 __TRACE__=1
}

if (linux-g++-32):{
	message(Building x86/32 bit )
	QMAKE_CFLAGS	= -m32
	QMAKE_CXXFLAGS	= -m32
	QMAKE_LFLAGS	= -m32
	CONFIG	+= warn_off

	DEFINES		+= __ARCH__NAME__=\\\"i386\\\"

}

if (linux-g++-64):{
	message(Building x86/64 bit )
	QMAKE_CFLAGS	= -m64
	QMAKE_CXXFLAGS	= -m64
	QMAKE_LFLAGS	= -m64

	DEFINES		+= __ARCH__NAME__=\\\"x86_64\\\"
}
