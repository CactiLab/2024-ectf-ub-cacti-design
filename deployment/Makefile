
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1$(if $2, ($2))))

all: keygen aead_keygen
	./keygen.elf priv=ap_priv.bin pub=ap_pub.bin
	./keygen.elf priv=cp_priv.bin pub=cp_pub.bin
	./aead_key.elf key=aead_key.bin nonce=aead_nonce.bin nonce_cp_boot=aead_nonce_cp_boot.bin

keygen: keygen.c monocypher.c
	gcc -o keygen.elf keygen.c monocypher.c

aead_keygen: aead_key.c monocypher.c
	gcc -o aead_key.elf aead_key.c monocypher.c

clean:
	rm -f *.elf *.bin