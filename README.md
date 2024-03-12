# Secure-key-exchange-AES-and-RSA
AES is a symmetric cryptographic algorithm that was established by the U.S. National Institute of Standards and Technology (NIST) in 2001. AES is a block cipher used for encrypting electronic data and relies on a substitution-permutation network principle, involving the replacement and shuffling of input data. AES is referred to as a symmetric algorithm because it uses a single secret key for both encryption and decryption processes. This implies that for two parties to communicate securely using the AES algorithm, they must both have the secret key. This raises the question, how do you securely share this secret key? To solve this, The RSA algorithm is often introduced alongside AES to address the challenge of securely sharing the secret key. RSA is an asymmetric cryptographic algorithm that uses a pair of keys: a public key, which can be shared openly, and a private key, which is kept secret. Here’s a brief breakdown of how it works with AES:
The sender uses the recipient’s public RSA key to encrypt the AES secret key.
The encrypted AES key is then safely transmitted to the recipient.
Upon receiving it, the recipient uses their private RSA key to decrypt the AES key. Now both parties have the AES key for secure communication.
Additionally, a private signature could be added to ensure non-repudiation and confirm that the secret key is coming from the appropriate source.

Here's a typical scenario and its implementation:

Alex and Bob want to communicate their confidential messages using the Advanced Encryption Standard (AES) algorithm. To do this, they must first exchange a secret key for AES using the RSA algorithm before communicating confidential messages. This project implements a secret key exchange using the RSA algorithm between Alex and Bob. After which they then share messages securely with AES using the earlier shared key. A breakdown of the process is as follows:
Alex will create a secret key for AES and sign on the key, sending the key and signature to Bob using the RSA algorithm. 
After they exchange a secret key, Alex sends a message encrypted by AES to Bob, who decrypts the message to read. 
Bob will send a reply encrypted by AES back to Alex, who decrypts Bob’s reply. 


![image](https://github.com/Ijezue/Secure-key-exchange-AES-and-RSA/assets/94120756/6c5e66f3-45c5-434c-be9e-cd797d35dd0b)

