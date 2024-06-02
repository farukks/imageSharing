Faruk Akdemir  150119012

Yasin Sefa Kırman 150119034

Project Overview
This project implements an image sharing system with a focus on security. Users can register with the server, post encrypted images, and download images while ensuring the integrity and confidentiality of the data.

Design Choices
1. RSA Key Pair Generation
Server Side: The server generates an RSA key pair (2048 bits) for signing certificates and encrypting symmetric keys.
Client Side: Each user also generates an RSA key pair (2048 bits) for signing image data and decrypting symmetric keys.
2. User Registration and Certification
Certificate Signing: When a user registers, the server signs the user's public key along with their username to create a certificate. This certificate is used to verify the authenticity of the user's public key.
Public Key Storage: The server stores each user's public key and their corresponding certificate.
3. Image Encryption and Signing
Symmetric Encryption: Images are encrypted using AES with a 256-bit key in CBC mode. The AES key and initialization vector (IV) are randomly generated for each image.
Digital Signing: The SHA-256 hash of the original image data is created and signed using the user's private RSA key. This signature ensures the integrity and authenticity of the image.
AES Key Encryption: The AES key is encrypted using the server's public RSA key before being sent to the server. This ensures that only the server can decrypt the AES key.
4. Image Upload
Data Structure: The server stores the encrypted image, the digital signature, the encrypted AES key, and the IV. The server also records the owner of the image.
Notification: The server notifies all registered users when a new image is posted.
5. Image Download
AES Key Decryption: When a user requests to download an image, the server sends the encrypted AES key (encrypted with the requesting user's public key) along with the encrypted image, signature, owner's certificate, and IV.
Verification: The client decrypts the AES key, decrypts the image, and verifies the image's integrity using the owner's public key and the signature.
Potential Security Holes and Countermeasures
Potential Security Holes
Man-in-the-Middle Attack: If an attacker intercepts the communication between the client and the server, they could potentially alter the data or inject malicious content.
Key Management: If private keys are compromised, the security of the system is at risk. An attacker with access to a private key can impersonate a user.
Replay Attack: An attacker could capture and replay legitimate messages to perform unauthorized actions.
Denial of Service (DoS): An attacker could flood the server with registration or image upload requests to overwhelm the system.


Countermeasures
TLS/SSL: Implementing TLS/SSL for all communications between clients and the server can mitigate man-in-the-middle attacks by ensuring data is encrypted during transmission.
Secure Key Storage: Using secure storage mechanisms for private keys, such as hardware security modules (HSMs) or secure enclaves, can prevent key compromise.
Nonce/Token Mechanism: Implementing nonces or tokens for each transaction can prevent replay attacks by ensuring each request is unique.
Rate Limiting and Captchas: Implementing rate limiting and captchas for registration and image upload endpoints can mitigate DoS attacks by preventing automated abuse.


Conclusion
The image sharing system provides a secure method for users to share images by incorporating encryption, digital signatures, and certificate-based authentication. While the design addresses many security concerns, continuous evaluation and improvement of the system are necessary to address emerging threats and vulnerabilities.










