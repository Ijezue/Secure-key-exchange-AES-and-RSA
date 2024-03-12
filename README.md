# Secure-key-exchange-AES-and-RSA
Alex and Bob want to communicate their confidential messages using the Advanced Encryption
Standard (AES) algorithm. They exchange a secret key for AES using the RSA algorithm before
communicating confidential messages.
You are required to implement a secret key exchange using the RSA algorithm between Alex
and Bob (see Figure). Alex will create a secret key for AES and sign on the key, sending the key
and signature to Bob using the RSA algorithm. After they exchange a secret key, Alex sends a
message encrypted by AES to Bob, who decrypts the message to read. Bob will send a reply
encrypted by AES back to Alex, who decrypts Bob’s reply. 
