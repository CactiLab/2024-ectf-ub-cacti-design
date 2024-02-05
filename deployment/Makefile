
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1$(if $2, ($2))))

all: global_secrets.h keygen
	./keygen.elf priv=priv.bin pub=pub.bin

global_secrets.h:
	echo "#define SECRET 1234" > global_secrets.h

gen_key: gen_key.c
	gcc -o gen_key.elf gen_key.c -I$(MBEDTLS_PATH)/include -L$(MBEDTLS_PATH)/lib -lmbedtls -lmbedx509 -lmbedcrypto

ecdsa: ecdsa.c
	gcc -o ecdsa.elf ecdsa.c -I$(MBEDTLS_PATH)/include -L$(MBEDTLS_PATH)/lib -lmbedtls -lmbedx509 -lmbedcrypto

test: test.c monocypher.c
	gcc -o test.elf test.c monocypher.c

keygen: keygen.c monocypher.c
	gcc -o keygen.elf keygen.c monocypher.c

clean:
	rm -f global_secrets.h *.elf *.bin