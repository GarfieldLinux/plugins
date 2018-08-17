# Makefile

LIBNAME=ts_stale_revalidate.so
ATS_INSTALL_PATH=YOUR ATS INSTALL PATH 
TSXS=$(ATS_INSTALL_PATH)/bin/tsxs
LIBPATH=$(ATS_INSTALL_PATH)/libexec/trafficserver/
FILE_EX=c

all:
	$(TSXS) -o $(LIBNAME) -c *.$(FILE_EX)
	rm -rf *.lo

install:
	cp -Rpf $(LIBNAME) $(LIBPATH)

clean:
	-rm -rf *.lo *.so
