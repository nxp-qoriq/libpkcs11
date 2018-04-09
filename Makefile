# Default out dir.
O               ?= out

include flags.mk

#########################################################################
# Set Internal Variables						#
#########################################################################
BUILD_VERBOSE	?= 0
VPREFIX		?= @
ifeq ($(BUILD_VERBOSE),1)
VPREFIX:=
endif

EXPORT_DIR ?= $(O)/export
OUT_DIR ?= $(O)/libpkcs11

.PHONY: all libpkcs11 install \
	clean distclean app

all: libpkcs11 app install

LIB_NAME	:= libpkcs11.so

PKCS11_SRCS	:= p11_general.c \
		   general.c \
		   tee_slot.c \
		   sessions.c \
		   objects.c \
		   p11_session_slot.c \
		   p11_object.c \
		   p11_crypto.c \
		   crypto.c

PKCS11_SRC_DIR	:= src
PKCS11_OBJ_DIR	:= $(OUT_DIR)
PKCS11_OBJS 	:= $(patsubst %.c,$(PKCS11_OBJ_DIR)/%.o, $(PKCS11_SRCS))
PKCS11_INCLUDES	:= ${CURDIR}/include \
		   ${CURDIR}/public \
		   $(SECURE_OBJ_PATH)/include

PKCS11_CFLAGS	:= $(addprefix -I, $(PKCS11_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE

PKCS11_LIBRARY	:= $(OUT_DIR)/$(LIB_NAME)

libpkcs11: $(PKCS11_LIBRARY)
	@echo "Building libpkcs11.so" 	

$(PKCS11_LIBRARY): $(PKCS11_OBJS)	
	@echo "  LD      $@"
	$(VPREFIX)$(CC) -pthread -shared -Wl,-soname,$(LIB_NAME) -o $@ $+
	@echo ""

$(PKCS11_OBJ_DIR)/%.o: ${PKCS11_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(PKCS11_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(PKCS11_CFLAGS) -c $< -o $@

ifdef OPENSSL_PATH
OPENSSL := $(OPENSSL_PATH)
else
OPENSSL := /usr/
endif

app:
	@echo "Building pkcs apps"
	$(VPREFIX)$(CC) -pthread -g -I$(OPENSSL)/include/ -L$(OPENSSL)/ -Iinclude/ -Ipublic/ \
		 -o app/thread_test app/thread_test.c -ldl -lssl -lcrypto -Lout/libpkcs11/
	$(VPREFIX)$(CC) -I$(OPENSSL)/include/ -L$(OPENSSL)/ -Iinclude/ -Ipublic/ \
		 -o app/utils.o app/utils.c \
		 -o app/pkcs11_app app/pkcs11_app.c \
		 -lpkcs11 -ldl -lssl -lcrypto -Lout/libpkcs11/

install:
	mkdir -p ${EXPORT_DIR}/lib ${EXPORT_DIR}/include ${EXPORT_DIR}/app images
	cp ${OUT_DIR}/libpkcs11.so ${EXPORT_DIR}/lib
	cp ${CURDIR}/public/*.h ${EXPORT_DIR}/include
	mv app/pkcs11_app ${EXPORT_DIR}/app
	mv app/thread_test ${EXPORT_DIR}/app
	cp ${OUT_DIR}/libpkcs11.so ${EXPORT_DIR}/app/pkcs11_app ${EXPORT_DIR}/app/thread_test images

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(O) images

distclean: clean
