LIBNAME := servers
SO := $(LIBNAME).so
SOURCES := $(wildcard src/*.c)
INCLUDES := $(wildcard include/*.h)
DEPS := -lpthread -lcjson
FLAGS := -fpic -shared

INSTALLED_SO := /usr/lib/lib$(SO)
INSTALLED_INCLUDES := $(patsubst include/%,/usr/include/%,$(INCLUDES))


all: $(SO)

clean:
	rm -f $(SO)

install: all
	sudo cp $(SO) $(INSTALLED_SO)
	sudo chown root:root $(INSTALLED_SO)
	sudo chmod 0775 $(INSTALLED_SO)
	sudo cp $(INCLUDES) /usr/include/
	sudo chown root:root $(INSTALLED_INCLUDES)
	sudo chmod 0664 $(INSTALLED_INCLUDES)

uninstall:
	sudo rm -f $(INSTALLED_SO) $(INSTALLED_INCLUDES)


$(SO): $(SOURCES) $(INCLUDES)
	gcc $(FLAGS) $(SOURCES) -I include -o $@ $(DEPS)


.PHONY: all clean install uninstall
.DEFAULT_GOAL := all
