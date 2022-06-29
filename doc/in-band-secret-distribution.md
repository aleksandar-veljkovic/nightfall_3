# In Band Secret Distribution

## Overview

To ensure a recipient receives the secret information required to spend their commitment, the sender
encrypts the secrets (salt, value, tokenId, ercAddress) of the commitment sent to the recipient and
proves using zkp that they encrypted this correctly with the recipient's public key. We use the 
KEM-DEM hybrid encryption paradigm.

## KEM-DEM Hybrid Encryption

### Key Creation

Use Elliptic curve (here we use Baby Jubjub curve) `E` over a finite field `Fp` where `p` is a large
prime and `G` is the generator.

Alice generates a random ephemeral asymmetric key-pair $(x_e, Q_e)$:  
$$ x_e \; \leftarrow\; \{0, 1\}^{256} \qquad Q_e \coloneqq x_eG $$

These keys are only used once, and are unique to this transaction, giving us perfect forward secerecy.

### Encryption

The encryption process involves 2 steps: a KEM step to derive a symmetric encryption key from a shared secret, and a DEM step to encrypt the plaintexts using the encryption key.

### Key Encapsulation Method (Encryption)
Using the previously generated asymmetric private key, we obtain a shared secret, $key_{DH}$, using standard Diffie-Hellman. This is hashed alongside the ephemeral public key to obtain the encryption key.
$$ key_{DH} \coloneqq x_eQ_r \qquad key_{enc} \coloneqq H_{K}(key_{DH} \; + \;Q_e)$$

where  
$Q_r$ is the recipient's public key  
$H_{K}(x) \coloneqq \text{MIMC}(Domain_{K}, x)$  
$Domain_{K} \coloneqq \text{to\_field}(\text{SHA256}(\text{'nightfall-kem'}))$


### Data Encapsulation Method (Encryption)
For circuit efficiency, the encryption used is a block cipher in counter mode where the cipher algorithm is a mimc hash. Given the ephemeral keys are unique to each transaction, there is no need for a nonce to be included. The encryption of the $i^{th}$ message is as follows:  

$$ c_i \coloneqq H_{D}(key_{enc} + i) + p_i$$  

where  
$H_{D}(x) \coloneqq \text{MIMC}(Domain_{D}, x)$  
$Domain_{D} \coloneqq \text{to\_field}(\text{SHA256}(\text{'nightfall-dem'}))$   

The sender then provides the recipient with $(Q_e, \text{ciphertexts})$. These are included as part of the transaction struct sent on-chain.

### Decryption
In order to decrypt, the recipient performs a slightly modified version of the KEM-DEM steps.
### Key Encapsulation Method (Decryption)
Given $Q_e$, the recipient is able to calculate the encryption key locally by performing the following steps.

$$key_{DH} \coloneqq x_eQ_e \qquad key_{enc} \coloneqq H_{K}(key_{DH} \; + \;Q_e)$$  

where  
$Q_e$ is the ephemeral public key  
$H_{K}(x) \coloneqq \text{MIMC}(Domain_{K}, x)$  
$Domain_{K} \coloneqq \text{to\_field}(\text{SHA256}(\text{'nightfall-kem'}))$

### Data Encapsulation Method (Decryption)
With $key_{enc}$ and an array of ciphertexts, the $i_{th}$ plaintext can be recovered with the following:  

$$p_i \coloneqq c_i - H_{D}(key_{enc} + i)$$  

where  
$H_{D}(x) \coloneqq \text{MIMC}(Domain_{D}, x)$  
$Domain_{D} \coloneqq \text{to\_field}(SHA256(\text{'nightfall-dem'}))$


## Derivation and generation of the various keys involved in encryption, ownership of commitments and spending

The names of the various keys follow the same terminology as zCash in order to make it easy for
those familiar with zCash speciifcation to follow this

Generate random secret keys `ask` and `nsk` which belong to the field with prime
`BN128_GROUP_ORDER`. `ask` will be used along with `nsk` to separate nullifying and proving
ownership. `nsk` is used in a nullifier along with the commitment. Next calculate incoming viewing
key `ivk` and diversified transmission key `pkd` as follows:

```
ivk = MiMC(ask, nsk)
pkd = ivk.G //used in a commitment to describe the owner as well as to encrypt secrets
```

Both `ask` and `nsk` will need to be securely stored separately from each other and should be rolled
from time to time. This way if one of `nsk` or `ask` is leaked, the adversary still cannot provide
proof of ownership which requires `ivk` which in turn requires knowlegde of `ask` or `nsk`
respectively. If both `ask` and `ivk` are leaked, one requires knowledge of `nsk` to nullify. If
both `nsk` and `ivk` are leaked, one requires knowledge of `ask` to show that they can derive `ivk`
to spend.

`pkd` will also be used in the encryption of secrets by a sender. This will need to be a point on
the elliptic curve and we derive this from `ivk` through scalar multiplication. `ivk` will be used
to decrypt the secrets. If `ivk` is leaked and as a result the secrets are known to the adversary,
they will still need knowledge of `ask` and `nsk` to spend a commitment.

### Acknowledgements

Some of the work for in band secret distribution is inspired by zCash. Grateful for their work in
this field.
