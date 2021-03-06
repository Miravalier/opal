LIBNAME := opal
SO := $(LIBNAME).so
SOURCES := $(wildcard src/*.c)
INCLUDES := $(wildcard include/$(LIBNAME)/*.h)
PYTHON_LIBS := $(wildcard python/*.py)
DEPS := -lpthread -lcjson -lsodium
C_FLAGS := -fpic -shared -Wall -Wextra
CPP_FLAGS :=

INSTALLED_SO := /usr/lib/lib$(SO)
INSTALLED_INCLUDE_DIR := /usr/include/$(LIBNAME)
INSTALLED_PYTHON_DIR := /usr/lib/python3/dist-packages/$(LIBNAME)

release: $(SO)
release: CPP_FLAGS += -DNDEBUG
release: STRIP := on

debug: $(SO)
debug: FLAGS += -g
debug: CPP_FLAGS += -DDEBUG
debug: STRIP := off

clean:
	rm -f $(SO)

install: release
	sudo cp $(SO) $(INSTALLED_SO)
	sudo chown root:root $(INSTALLED_SO)
	sudo chmod 0775 $(INSTALLED_SO)
	sudo mkdir -p $(INSTALLED_INCLUDE_DIR) $(INSTALLED_PYTHON_DIR)
	sudo cp $(INCLUDES) $(INSTALLED_INCLUDE_DIR)
	sudo cp $(PYTHON_LIBS) $(INSTALLED_PYTHON_DIR)
	sudo chown -R root:root $(INSTALLED_INCLUDE_DIR) $(INSTALLED_PYTHON_DIR)
	sudo chmod 0775 $(INSTALLED_INCLUDE_DIR) $(INSTALLED_PYTHON_DIR)
	sudo chmod 0664 $(INSTALLED_INCLUDE_DIR)/* $(INSTALLED_PYTHON_DIR)/*

uninstall:
	sudo rm -rf $(INSTALLED_SO) $(INSTALLED_INCLUDE_DIR) $(INSTALLED_PYTHON_DIR)


$(SO): $(SOURCES) $(INCLUDES)
	gcc $(C_FLAGS) $(CPP_FLAGS) $(SOURCES) -I include -o $@ $(DEPS)
	@if [ "$(STRIP)" = "on" ]; then strip --strip-all $@; fi


.PHONY: release clean install uninstall
.DEFAULT_GOAL := release
