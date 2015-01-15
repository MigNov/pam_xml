bin_PROGRAMS = pam_xml
pam_xml_SOURCES = parser.c xml.c pam_xml.c database.c xml.h
pam_xml_CFLAGS = -Wall -lcurl -shared -fPIC -ldl -lpam -lpq

if USE_PKGCONFIG
  pam_xml_CPPFLAGS = `@PKGCONFIG@ libxml-2.0 --cflags`
endif

all:
	mv pam_xml libpam_xml.so
	$(CC) -o pam_example pam_example.c -lpam_xml -L.

test:
	 LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:. ./pam_example ../data/pam-test.xml

inst:
	sudo rm -f /usr/lib64/security/pam_xml.so
	sudo cp libpam_xml.so /usr/lib64/security/pam_xml.so
	echo "Done"
