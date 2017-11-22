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

.PHONY: all libpkcs11 install copy_export \
	clean distclean app

all: libpkcs11 app install

################################################################################
# TEE_PKCS11 configuration
################################################################################
LIB_NAME	:= libpkcs11.so

PKCS11_SRCS	:= pkcs11_crypto.c \
		   pkcs11_general.c \
		   pkcs11_object.c \
		   pkcs11_session_slot.c

PKCS11_SRC_DIR	:= src
PKCS11_OBJ_DIR	:= $(OUT_DIR)
PKCS11_OBJS 	:= $(patsubst %.c,$(PKCS11_OBJ_DIR)/%.o, $(PKCS11_SRCS))
PKCS11_INCLUDES	:= $(OPTEE_CLIENT_EXPORT)/include \
		   ${CURDIR}/include \
		   ${CURDIR}/public

PKCS11_CFLAGS	:= $(addprefix -I, $(PKCS11_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE \
		   -DBINARY_PREFIX=\"TEE_PKCS11\"

PKCS11_LFLAGS	:= -L$(OPTEE_CLIENT_EXPORT)/lib -lteec
PKCS11_LIBRARY	:= $(OUT_DIR)/$(LIB_NAME)

libpkcs11: $(PKCS11_LIBRARY)
	@echo "Building libpkcs11.so" 	

$(PKCS11_LIBRARY): $(PKCS11_OBJS)	
	@echo "  LD      $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_NAME) $(PKCS11_LFLAGS) -o $@ $+
	@echo ""

$(PKCS11_OBJ_DIR)/%.o: ${PKCS11_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(PKCS11_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(PKCS11_CFLAGS) -c $< -o $@

app:
	@echo "Building pkcs app"
	$(VPREFIX)$(CC) -Ipublic/ -o app/pkcs_app app/pkcs11_test_app.c -ltee_pkcs11 -lteec -Lout/libpkcs11/ -L../optee_client/out/libteec

install: copy_export

copy_export:
	mkdir -p ${EXPORT_DIR}/lib ${EXPORT_DIR}/include images
	cp ${OUT_DIR}/libpkcs11.so ${EXPORT_DIR}/lib
	cp ${CURDIR}/public/*.h ${EXPORT_DIR}/include
	cp ${OUT_DIR}/libpkcs11.so app/pkcs_app images

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(OUT_DIR)
	rm app/pkcs_app
	rm -rf images

distclean: clean
