# JWS & Ed25519

Supporting Ed25519 and JWS.

## Introduction

This small project shows how to use [Google Tink](https://github.com/google/tink) alongside [Nimbus JOSE](https://bitbucket.org/connect2id/nimbus-jose-jwt/wiki/Home)
to support the [Ed25519 public-key signature](https://ed25519.cr.yp.to/) as it is becoming more and more popular and used in distributed ledgers.

The standard Java SDK will only support natively EdDSA from version [15](https://openjdk.java.net/projects/jdk/15/), see [JEP 339](https://openjdk.java.net/jeps/339), whose general
availability will be on 15th, Sept, 2020.  
The proposed implementation uses [BouncyCastle](https://www.bouncycastle.org/).

## Libs
Refer to [build.gradle](./build.gradle) for the libs used in this project.

## JWT
Many resources exist to understand JWT but I would recommend this short list:
- [JWT, JWS and JWE for Not So Dummies!](https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3)
- [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)](https://tools.ietf.org/html/rfc8037)

## Code

### Key Pair Generation
Even though one can use [Google Tink](https://github.com/google/tink) to generate a Ed25519 key pair, I purposely doing to do this with  [BouncyCastle](https://www.bouncycastle.org/).

```java
Security.addProvider(new BouncyCastleProvider());
final Ed25519KeyPairGenerator ed25519KeyPairGenerator = new Ed25519KeyPairGenerator();
ed25519KeyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
final AsymmetricCipherKeyPair asymmetricCipherKeyPair = ed25519KeyPairGenerator.generateKeyPair();
final Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
final Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();
```

### OKP
As per [rfc8037]((https://tools.ietf.org/html/rfc8037)), next step is to generate a object of type 'OKP'.

```java
final String x = edPublicKey;
final String d = edPrivateKey;
final OctetKeyPair octetKeyPairJWK = new OctetKeyPair.Builder(Curve.Ed25519, new Base64URL(x)).d(new Base64URL(d)).build();
```

The JSON representation of the octetKeyPairJWK object is:

```json
{"kty":"OKP","d":"o11uN0ai0QZhk2NhrLsaRLtLHAbIyfzwKxyH_XjXO9I=","crv":"Ed25519","x":"SxWU8R32zZliBiC7xOgDFq2AduGgjZ4zKjyAAcbgugI="}
```

### JWS
The next step is the creation of JWS on a given payload:

```java
final JWSSigner signer = new Ed25519Signer(octetKeyPairJWK);
final String payload = "Edward, what have you done?";

final JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(octetKeyPairJWK.getKeyID()).build(),bnew Payload(payload));

jwsObject.sign(signer);

final String jws = jwsObject.serialize();
```
Follows the JSON representation of the JWS token:

```json
eyJhbGciOiJFZERTQSJ9.RWR3YXJkLCB3aGF0IGhhdmUgeW91IGRvbmU_.WnfnZYZUxMCkO_9SSIrqD8963WifoT-LtABf2CSVmzgiUwdl-yRloFBb-vFvRSh-MIOINd1EDIVmFDs-rk8JAQ
```

### Verification
```java
final JWSVerifier verifier = new Ed25519Verifier(octetKeyPairJWK.toPublicJWK());
assert jwsObject.verify(verifier);
```

That's it. Enjoy.