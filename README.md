# CryptologyJava

libsodium compatible CryptoSign, SealedBox and SecretBox implementation in Java.

## Download

Include in your project using Maven:

```xml
<dependency>
    <groupId>io.xconn</groupId>
    <artifactId>cryptology</artifactId>
    <version>0.1.0</version>
</dependency>
```

Or with Gradle:

```groovy
implementation 'io.xconn:cryptology:0.1.0'
```

## Usage

### CryptoSign

Generate ED25519 KeyPair

```java
KeyPair keyPair = CryptoSign.generateKeyPair();
```

Get PublicKey from PrivateKey

```java
byte[] privateKey = // ED25519 private key bytes
byte[] publicKey = CryptoSign.getPublicKey(privateKey);
```

Sign Message

```java
byte[] privateKey = // ED25519 private key bytes
byte[] message = "Hello, world!".getBytes();
byte[] signature = CryptoSign.sign(privateKey, message);
```

### SealedBox

Seal Message

```java
byte[] recipientPublicKey = // X25519 recipient's public key bytes
byte[] message = "Secret message".getBytes();
byte[] encryptedMessage = SealedBox.seal(message, recipientPublicKey);
```

Open Sealed Message

```java
byte[] privateKey = // X25519 recipient's private key bytes
byte[] sealedMessage = // Sealed message bytes
byte[] decryptedMessage = SealedBox.sealOpen(sealedMessage, privateKey);
```

### SecretBox

Encrypt Message

```java
byte[] nonce = SecretBox.generateNonce();
byte[] secretKey = SecretBox.generateSecret();
byte[] message = "Secret message".getBytes();
byte[] encryptedMessage = SecretBox.box(nonce, message, secretKey);
```

Decrypt Message

```java
byte[] nonce = // Nonce bytes
byte[] secretKey = // Secret key bytes
byte[] sealedMessage = // Sealed message bytes
byte[] decryptedMessage = SecretBox.boxOpen(sealedMessage, nonce, secretKey);
```