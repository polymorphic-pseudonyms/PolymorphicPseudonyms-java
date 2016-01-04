# Polymorphic Pseudonym - Java Implementation
This is the java implementation for polymorphic pseudonyms, as descibed in http://eprint.iacr.org/2015/1228.

## Class description
### IdP
Provides the functionality needed by identity providers: generating polymorphic pseudonyms for users.

### Party
Provides the functionality for decrypting encrypted pseudonyms.

### Pseudonym
A triple (A, B, C) of ECPoints, forming polymorphic or encrypted pseudonyms. Includes functionality for encoding and decoding pseudonyms.

### PPKeyPair
A public key pair that can be used for polymorphic pseudonyms.

### PF
Provides the functionality needed by a pseudonym facility: generating encryted pseudonyms from a polymorphic pseudonym for a given service provider.

### KMA
Provides the functionality needed by the key management authority. It generates the system wide public key pair, the key pairs for all parties and a diversification key D_k.

### SystemParams
Provides the paramaters for the used curve: brainpoolp320r1.

### Util
Provides some functions that are used on different places in the library: a Key Diversification Function (KDF), a function to embed data as a point on the elliptic curve, a hash function and secure random functions.
