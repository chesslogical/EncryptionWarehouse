


Example using AES key mode (assumes aes.key file exists in current directory with exactly 32 bytes and 0600 permissions):

Encrypt: ./ai aes enc test.txt

Decrypt: ./ai aes dec test.txt

Example using AES password mode:

Encrypt: ./ai aes enc test.txt -p

Decrypt: ai ./aes dec test.txt -p



Example using ChaCha key mode (assumes cha.key file exists in current directory with exactly 32 bytes and 0600 permissions):

Encrypt: ai cha enc test.txt

Decrypt: ai cha dec test.txt

Example using ChaCha password mode:

Encrypt: ai cha enc test.txt -p

Decrypt: ai cha dec test.txt -p




quickly populate test keys  

echo -n "defaulttestkeyaes123456789012345" > aes.key && chmod 600 aes.key && echo -n "defaulttestkeycha123456789012345" > cha.key && chmod 600 cha.key
