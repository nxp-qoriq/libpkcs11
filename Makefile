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
		   tee_slot.c \
		   p11_session_slot.c

PKCS11_SRC_DIR	:= src
PKCS11_OBJ_DIR	:= $(OUT_DIR)
PKCS11_OBJS 	:= $(patsubst %.c,$(PKCS11_OBJ_DIR)/%.o, $(PKCS11_SRCS))
PKCS11_INCLUDES	:= ${CURDIR}/include \
		   ${CURDIR}/public

PKCS11_CFLAGS	:= $(addprefix -I, $(PKCS11_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE \
		   -DBINARY_PREFIX=\"TEE_PKCS11\"

PKCS11_LIBRARY	:= $(OUT_DIR)/$(LIB_NAME)

libpkcs11: $(PKCS11_LIBRARY)
	@echo "Building libpkcs11.so" 	

$(PKCS11_LIBRARY): $(PKCS11_OBJS)	
	@echo "  LD      $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_NAME) -o $@ $+
	@echo ""

$(PKCS11_OBJ_DIR)/%.o: ${PKCS11_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(PKCS11_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(PKCS11_CFLAGS) -c $< -o $@

app:
	@echo "Building pkcs app"
	$(VPREFIX)$(CC) -Iinclude/ -Ipublic/ -o app/gen_test app/gen_test.c -lpkcs11 -ldl -Lout/libpkcs11/

install:
	mkdir -p ${EXPORT_DIR}/lib ${EXPORT_DIR}/include ${EXPORT_DIR}/app
	cp ${OUT_DIR}/libpkcs11.so ${EXPORT_DIR}/lib
	cp ${CURDIR}/public/*.h ${EXPORT_DIR}/include
	mv app/gen_test ${EXPORT_DIR}/app

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(O)

distclean: clean
