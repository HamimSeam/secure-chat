# secure-chat
Contributors: Hamim Seam and Angus Chen

## Libraries Used
- OpenSSL (for RSA, HMAC, AES)
- GTK+3 (for GUI)
- GMP (GNU Multiple Precision arithmetic library)
- pthreads – for multi-threading (to handle incoming messages without blocking the UI)

- MacOS installation: brew install openssl@3 gtk+3 gmp
- Linux/WSL installation: sudo apt install libssl-dev libgtk-3-dev libgmp-dev

### Usage
- Compilation: `make`
- Compilation (MacOS): "make -f Makefile.os"
- Running: `./chat -l & sleep 1 && ./chat -c localhost`
    Note: This will run both server and client in the same terminal window. For clarity, use two separate terminals.

## Project Structure
- `chat.c`: Main GUI and network loop
- `util.c/h`: RSA signature and HMAC utilities
- `dh.c/h`: Diffie-Hellman logic
- `keys.c/h`: RSA key generation and serialization
- `Makefile` / `Makefile.macos`: Build files (Linux/WSL and macOS)

### Procedure
1. Server and client generate public and private RSA keys before establishing a connection.
	- The keys are already stored in the project's `keys` directory.
	- If the keys are not present, use `generate_rsa_keys` to create them.
2. Server and client generate a Diffie-Hellman key pair, using the functions in `dh.c`.
3. Server and client each sign their public Diffie-Hellman keys with their private RSA keys, and send this signature over the channel.
4. Both parties verify the received signature using the other party's public RSA key, ensuring that it matches the Diffie-Hellman public key, establishing authentication.
5. The Diffie-Hellman shared secret, generated by each party from their own secret keys and the received public keys is used as the key for HMAC.
6. Every message sent is sent along with its corresponding HMAC. If the HMAC is verified to match the message, integrity is established.

### Notes
- All of the student-written functions are written in `util.c`, and called in `chat.c`.
- There is a known bug where messages are sometimes doubled -- we speculate this is related to how much we read/write to the socket from our buffers.
