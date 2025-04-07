rsa_sign: rsa_sign.c -lssl -lcrypto
	gcc -o rsa_sign rsa_sign.c ../util.c ../dh.c -lssl -lcrypto -lgmp

clean:
	rm -f *.o
	rm -f rsa_sign
