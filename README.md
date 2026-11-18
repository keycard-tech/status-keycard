# What is Keycard?

Keycard is an implementation of a BIP-32 HD wallet running on Javacard 3.0.5 (see implementation notes)

It supports among others
- key generation, derivation and signing
- exporting keys defined in the context of EIP-1581 https://eips.ethereum.org/EIPS/eip-1581
- setting up a NFC NDEF tag

Communication with the Keycard happens through a simple APDU interface, together with a Secure Channel guaranteeing confidentiality, authentication and integrity of all commands. It supports both NFC and ISO7816 physical interfaces, meaning that it is compatible with any Android phone equipped with NFC, and all USB Smartcard readers.

The most obvious case for integration of Keycard is crypto wallets (ETH, BTC, etc), however it can be used in other systems where a BIP-32 key tree is used and/or you perform authentication/identification.

# Where to start?

A good place to start is our [documentation site](https://keycard.tech/docs/)

Keycard is a public good — contributions are welcome and highly encouraged!

You can also join the discussion about this project on our [discord channel](https://discord.gg/uJAXk7jFhZ)

Keycard is at the center of several projects, check the [ecosystem of projects](https://github.com/keycard-tech/keycard-ecosystem-projects/) or [good first issues](https://github.com/orgs/keycard-tech/projects/1/views/2?filterQuery=good+first+issue)

Should you wish to work on an issue, please claim it first by commenting on the GitHub issue that you want to work on it. This is to prevent duplicated efforts from contributors on the same issue. 

If you just want to use Keycard as your hardware wallet, you can choose from any compatible wallet in this list (apply the 'Keycard' filter): https://keycard.tech/wallets/

# How to build the project?

**YOU NEED OPENJDK11 TO BUILD THIS PROJECT**

make sure your `JAVA_HOME` environment variable points to a working OpenJDK 11 installation. This is a prerequisite for all of the following steps.

## Get the source

Clone this repository with `git clone --recurse-submodules https://github.com/keycard-tech/status-keycard`

## Compilation

Run `./gradlew convertJavacard`

## Installation

`./gradlew install` runs [keycard-cli](https://github.com/keycard-tech/keycard-cli), which is downloaded from its GitHub releases the first time it is needed, checked against the digests in `buildSrc/src/main/resources/keycard-cli.properties` and cached in the Gradle home. The applets are reinstalled over the previous installation on every run.

The card needs the T=1 protocol. Security Domains speaking SCP02 or SCP03 both work, since the protocol is read from the card's answer, and cards using one of the public development keys need no further setup.

1. Put the card in a reader and run `./gradlew install`
2. With more than one reader connected, select the one holding the card: `./gradlew install -Pim.status.keycard.reader="ACS ACR122U PICC Interface 00 00"`
3. For a card loaded with other GlobalPlatform keys, give the key to the environment rather than to the command line: `KEYCARD_GP_MAC_KEY=<hex> ./gradlew install`

To install with a keycard-cli you built yourself, or on a machine that cannot reach github.com, point the build at it with `-Pim.status.keycard.cli.path=/path/to/keycard`.

## Testing

Run `./gradlew test`

if you want to test using the simulator instead of a real card, create a file named `gradle.properties` with the content:

```im.status.keycard.test.target=simulator```

before running the tests.

# What kind of smartcards can I use? 
* The applet requires JavaCard 3.0.5 or later.
* The class byte of the APDU is not checked since there are no conflicting INS code.
* The GlobalPlatform ISD runs SCP02 or SCP03, with keys set to 404142434445464748494a4b4c4d4e4f (GlobalPlatform default keys) or c212e073ff8b4bbfaff4de8ab655221f (Keycard development cards default keys). Cards personalized with other keys are supported too, see [installation](#installation).
* The exact list of algorithms the card must or can support is as follows.
  * Must be supported and is part of JavaCard 3.0.5:
    * KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY
  * Must be supported and is part of JavaCard 3.0.4:
    * Cipher.ALG_AES_BLOCK_128_CBC_NOPAD
    * Cipher.ALG_AES_CBC_ISO9797_M2
    * KeyAgreement.ALG_EC_SVDP_DH_PLAIN
    * KeyPair.ALG_EC_FP (generation of 256-bit keys)
    * MessageDigest.ALG_SHA_256
    * MessageDigest.ALG_SHA_512
    * RandomData.ALG_SECURE_RANDOM
    * Signature.ALG_AES_MAC_128_NOPAD
    * Signature.ALG_ECDSA_SHA_256
  * Can be supported and is part of 3.0.5 
    * Signature.ALG_HMAC_SHA_512 (improves performance)
* A good resource that tracks which algorithm is supported by which card is https://www.fi.muni.cz/~xsvenda/jcalgtest/

# Other related repositories

Java SDK for Android and Desktop https://github.com/keycard-tech/status-keycard-java

Swift SDK for iOS13 and above https://github.com/keycard-tech/Keycard.swift

Keycard CLI for Desktop https://github.com/keycard-tech/keycard-cli
