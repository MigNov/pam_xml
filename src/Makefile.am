bin_PROGRAMS = pam_xml
pam_xml_SOURCES = parser.c xml.c pam_xml.c xml.h
pam_xml_CFLAGS = -Wall -lcurl -shared -fPIC -ldl

if USE_PKGCONFIG
  pam_xml_CPPFLAGS = `@PKGCONFIG@ libxml-2.0 --cflags`
endif

all:
	mv pam_xml pam_xml.so
