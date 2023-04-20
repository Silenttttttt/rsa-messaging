# RSA Encryption/Decryption Messaging System

This Python program allows users to generate RSA key pairs, share public keys, and encrypt/decrypt messages. The interface is built using PySimpleGUI and the encryption/decryption functionality uses the pycryptodome library.


Dependencies
  Python 3.x
  PySimpleGUI
  pycryptodome


To install the dependencies, run:

`pip install PySimpleGUI pycryptodome`



How to use

Run the program:


`python rsa_messaging_system.py`
1 - When you run the program for the first time, press generate RSA to generate a new key pair. Your public address (`public key`) will be displayed in the interface.

2 - Share your public address (`public key`) with others so they can use it to encrypt messages they want to send to you. Remember, never share your private key.

3 - To encrypt a message, paste the recipient's public key into the "Public Key To Encrypt Message" box. Then, enter the message you want to encrypt in the "Message To Encrypt/Decrypt" box. Click the "Encrypt" button, and the encrypted message will appear in the "Encrypted/Decrypted Message" box.

4 - To decrypt a message, paste your private key (if it's not already there) into the "Private Key" box. Then, copy the encrypted message into the "Encrypted/Decrypted Message" box. Click the "Decrypt" button, and the decrypted message will appear in the same box.

5 - To copy any of the text from the program (public address, private key, public key, message, or encrypted/decrypted message), click the corresponding "Copy" button.

6 - To clear any of the text boxes (private key, public key, message, or encrypted/decrypted message), click the corresponding "Clear" button.

7 - If you want to generate a new RSA key pair, click the "Generate Key Pair" button. Keep in mind that generating a new key pair will make your previous public address (`public key`) and private key unusable.


Always remember to keep your `private key` safe and never share it with anyone.
