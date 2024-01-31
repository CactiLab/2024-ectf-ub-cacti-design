
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1$(if $2, ($2))))

all: global_secrets.h gen_key
	./gen_key type=ec ec_curve=x25519 format=der use_dev_random=1

global_secrets.h:
	echo "#define SECRET 1234" > global_secrets.h

gen_key: gen_key.c
	gcc -o gen_key gen_key.c -I$(MBEDTLS_PATH)/include -L$(MBEDTLS_PATH)/lib -lmbedtls -lmbedx509 -lmbedcrypto

clean:
	rm -f global_secrets.h gen_key keyfile.key