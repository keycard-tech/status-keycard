package im.status.keycard;

import im.status.keycard.math.BigNumberMath;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Crypto utilities, mostly BIP32 related. The init method must be called during application installation. This class
 * is not meant to be instantiated.
 */
public class Crypto {
  final static public short AES_BLOCK_SIZE = 16;

  final static short KEY_SECRET_SIZE = 32;
  final static short KEY_PUB_SIZE = 65;
  final static short KEY_DERIVATION_SCRATCH_SIZE = 37;
  final static private short HMAC_OUT_SIZE_512 = MessageDigest.LENGTH_SHA_512;
  final static private short HMAC_OUT_SIZE_256 = MessageDigest.LENGTH_SHA_256;

  final static private byte[] MAX_S = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4, (byte) 0x50, (byte) 0x1D, (byte) 0xDF, (byte) 0xE9, (byte) 0x2F, (byte) 0x46, (byte) 0x68, (byte) 0x1B, (byte) 0x20, (byte) 0xA0 };
  final static private byte[] S_SUB = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B, (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41 };

  final static private byte HMAC_IPAD = (byte) 0x36;
  final static private byte HMAC_OPAD = (byte) 0x5c;
  final static private short HMAC_BLOCK_SIZE_512 = (short) 128;
  final static private short HMAC_BLOCK_SIZE_256 = (short) 64;

  final static byte[] KEY_BITCOIN_SEED = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
  final static byte[] KEY_LEE_PUB_SEED = {'L', 'E', 'E', '_', 'm', 'a', 's', 't', 'e', 'r', '_', 'p', 'u', 'b'};
  final static byte[] KEY_LEE_PRIV_SEED =  {'L', 'E', 'E', '_', 'm', 'a', 's', 't', 'e', 'r', '_', 'p', 'r', 'i', 'v'};
  private final static byte[] LEE_SEED_PRIV = {'L', 'E', 'E', '_', 's', 'e', 'e', 'd', '_', 'p', 'r', 'i', 'v'};
  private final static byte[] LEE_KEY = {'L', 'E','E', '/', 'k', 'e', 'y', 's'};

  final static byte CONST_NSK = 0x01;
  final static byte CONST_VSK = 0x02;
  final static byte CONST_NPK = 0x07;

  final static short SCRATCH_SIZE = (short) 176;

  final static short BIP0340_CHALLENGE = (short) 0;
  final static short BIP0340_AUX = MessageDigest.LENGTH_SHA_256;
  final static short BIP0340_NONCE = (short) 2 * MessageDigest.LENGTH_SHA_256;

  final static private byte[] TAGGED_PREFIXES = {
      // BIP0340_CHALLENGE
      (byte) 0x7b, (byte) 0xb5, (byte) 0x2d, (byte) 0x7a, (byte) 0x9f, (byte) 0xef, (byte) 0x58, (byte) 0x32,
      (byte) 0x3e, (byte) 0xb1, (byte) 0xbf, (byte) 0x7a, (byte) 0x40, (byte) 0x7d, (byte) 0xb3, (byte) 0x82,
      (byte) 0xd2, (byte) 0xf3, (byte) 0xf2, (byte) 0xd8, (byte) 0x1b, (byte) 0xb1, (byte) 0x22, (byte) 0x4f,
      (byte) 0x49, (byte) 0xfe, (byte) 0x51, (byte) 0x8f, (byte) 0x6d, (byte) 0x48, (byte) 0xd3, (byte) 0x7c,
      // BIP0340_AUX
      (byte) 0xf1, (byte) 0xef, (byte) 0x4e, (byte) 0x5e, (byte) 0xc0, (byte) 0x63, (byte) 0xca, (byte) 0xda,
      (byte) 0x6d, (byte) 0x94, (byte) 0xca, (byte) 0xfa, (byte) 0x9d, (byte) 0x98, (byte) 0x7e, (byte) 0xa0,
      (byte) 0x69, (byte) 0x26, (byte) 0x58, (byte) 0x39, (byte) 0xec, (byte) 0xc1, (byte) 0x1f, (byte) 0x97,
      (byte) 0x2d, (byte) 0x77, (byte) 0xa5, (byte) 0x2e, (byte) 0xd8, (byte) 0xc1, (byte) 0xcc, (byte) 0x90,
      // BIP0340_NONCE
      (byte) 0x07, (byte) 0x49, (byte) 0x77, (byte) 0x34, (byte) 0xa7, (byte) 0x9b, (byte) 0xcb, (byte) 0x35,
      (byte) 0x5b, (byte) 0x9b, (byte) 0x8c, (byte) 0x7d, (byte) 0x03, (byte) 0x4f, (byte) 0x12, (byte) 0x1c,
      (byte) 0xf4, (byte) 0x34, (byte) 0xd7, (byte) 0x3e, (byte) 0xf7, (byte) 0x2d, (byte) 0xda, (byte) 0x19,
      (byte) 0x87, (byte) 0x00, (byte) 0x61, (byte) 0xfb, (byte) 0x52, (byte) 0xbf, (byte) 0xeb, (byte) 0x2f,
  };

  final static private byte CCM_FLAGS_T8_Q2 = (byte) 0x19;
  final static private byte CTR_FLAGS_Q2 = (byte) 0x01;
  final static private short CCM_TAG_TMP_OFF = (short) 64;
  final static short CCM_NONCE_SIZE = 13;
  final static short CCM_TAG_SIZE = 8;

  // The below 5 objects can be accessed anywhere from the entire applet
  RandomData random;
  KeyAgreement ecdh;
  MessageDigest sha256;
  MessageDigest sha512;
  Cipher aesEcb;
  Signature aesCbcMac;

  Signature ecdsa;
  BigNumberMath bigMath;
  byte[] scratch;

  private Signature hmacSHA512;
  private Signature hmacSHA256;
  private HMACKey hmacKey;

  private byte[] hmacBlock;

  Crypto() {
    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    aesEcb = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    aesCbcMac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
    ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    scratch = JCSystem.makeTransientByteArray(SCRATCH_SIZE, JCSystem.CLEAR_ON_DESELECT);
    bigMath = new BigNumberMath();

    try {
      hmacSHA512 = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
      hmacSHA256 = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
      hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    } catch (CryptoException e) {
      hmacSHA512 = null;
      hmacSHA256 = null;
      hmacBlock = JCSystem.makeTransientByteArray(HMAC_BLOCK_SIZE_512, JCSystem.CLEAR_ON_RESET);
    }

  }


  /**
   * Computes the AES-CCM authentication tag via CBC-MAC.
   *
   * @param nonce the nonce (13 bytes)
   * @param nonceOff the offset of the nonce
   * @param data the data to authenticate
   * @param dataOff the offset of the data
   * @param dataLen the length of the data
   */
  private void aesCcmComputeMac(AESKey aesKey, byte[] nonce, short nonceOff, byte[] data, short dataOff, short dataLen) {
    // Build formatted block: flags | nonce | EncLen (2 bytes big-endian)
    scratch[0] = CCM_FLAGS_T8_Q2;
    Util.arrayCopyNonAtomic(nonce, nonceOff, scratch, (short) 1, CCM_NONCE_SIZE);
    scratch[(short) 14] = (byte) ((dataLen >> 8) & 0xFF);
    scratch[(short) 15] = (byte) (dataLen & 0xFF);

    aesCbcMac.init(aesKey, Signature.MODE_SIGN);

    if (dataLen == 0) {
      aesCbcMac.sign(scratch, (short) 0, AES_BLOCK_SIZE, scratch, CCM_TAG_TMP_OFF);
    } else {
      aesCbcMac.update(scratch, (short) 0, AES_BLOCK_SIZE);

      short completeBytes = (short) ((dataLen / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
      short remaining = (short) (dataLen - completeBytes);

      aesCbcMac.update(data, dataOff, completeBytes);
      
      if (remaining > 0) {
        Util.arrayCopyNonAtomic(data, (short) (dataOff + completeBytes), scratch, (short) 0, remaining);
        Util.arrayFillNonAtomic(scratch, remaining, (short) (AES_BLOCK_SIZE - remaining), (byte) 0);
        aesCbcMac.sign(scratch, (short) 0, AES_BLOCK_SIZE, scratch, CCM_TAG_TMP_OFF);
      } else {
        aesCbcMac.sign(scratch, (short) 0, (short) 0, scratch, CCM_TAG_TMP_OFF);        
      }
    }
  }

  /**
   * AES-CCM counter-mode encryption/decryption (XOR with keystream).
   *
   * @param nonce the nonce (13 bytes)
   * @param nonceOff the offset of the nonce
   * @param input the input data (plaintext for encryption, ciphertext for decryption)
   * @param inOff the offset of the input
   * @param inLen the length of the input
   * @param output the output buffer
   * @param outOff the offset in the output buffer
   * @param tag the tag buffer
   * @param tagOff the outputBuffer
   */
  private void aesCcmCtrCrypt(AESKey aesKey, byte[] nonce, short nonceOff, byte[] input, short inOff, short inLen, byte[] output, short outOff, byte[] tag, short tagOff) {
    aesEcb.init(aesKey, Cipher.MODE_ENCRYPT);

    // Build the base counter block: flags | nonce | 00 00
    scratch[0] = CTR_FLAGS_Q2;
    Util.arrayCopyNonAtomic(nonce, nonceOff, scratch, (short) 1, CCM_NONCE_SIZE);
    scratch[(short) 14] = 0;
    scratch[(short) 15] = 0;

    aesEcb.doFinal(scratch, (short) 0, AES_BLOCK_SIZE, scratch, AES_BLOCK_SIZE);
    for (short i = 0; i < CCM_TAG_SIZE; i++) {
      tag[(short) (tagOff + i)] = (byte) (tag[(short) (tagOff + i)] ^ scratch[(short) (i + AES_BLOCK_SIZE)]);
    }

    short numBlocks = (short) ((short) (inLen + (short) (AES_BLOCK_SIZE - 1)) / (short) AES_BLOCK_SIZE);
    for (short i = 1; i <= numBlocks; i++) {
      scratch[(short) 14] = (byte) ((i >> 8) & 0xFF);
      scratch[(short) 15] = (byte) (i & 0xFF);

      aesEcb.doFinal(scratch, (short) 0, AES_BLOCK_SIZE, scratch, AES_BLOCK_SIZE);

      short blockStart = (short) ((i - 1) * AES_BLOCK_SIZE);
      short blockLen = (short) (i == numBlocks ? inLen - blockStart : AES_BLOCK_SIZE);

      for (short j = 0; j < blockLen; j++) {
        output[(short) (outOff + blockStart + j)] = (byte) (input[(short) (inOff + blockStart + j)] ^ scratch[(short) (j + AES_BLOCK_SIZE)]);
      }
    }
  }

  /**
   * AES-CCM generation-encryption (encrypt and authenticate).
   *
   * @param aesKey the AES-128 key
   * @param nonce the nonce (13 bytes)
   * @param nonceOff the offset of the nonce
   * @param plaintext the plaintext
   * @param ptOff the offset of the plaintext
   * @param ptLen the length of the plaintext
   * @param out the output buffer for ciphertext
   * @param outOff the offset in the ciphertext buffer
   */
  void aesCcmEncrypt(AESKey aesKey, byte[] nonce, short nonceOff, byte[] plaintext, short ptOff, short ptLen, byte[] out, short outOff) {
    short tagOff = (short) (outOff + ptLen);
    aesCcmComputeMac(aesKey, nonce, nonceOff, plaintext, ptOff, ptLen);
    aesCcmCtrCrypt(aesKey, nonce, nonceOff, plaintext, ptOff, ptLen, out, outOff, scratch, CCM_TAG_TMP_OFF);
    Util.arrayCopyNonAtomic(scratch, CCM_TAG_TMP_OFF, out, tagOff, CCM_TAG_SIZE);
  }

  /**
   * AES-CCM decryption-verification (decrypt and authenticate).
   *
   * @param aesKey the AES-128 key
   * @param nonce the nonce (13 bytes)
   * @param nonceOff the offset of the nonce
   * @param input the ciphertext || tag
   * @param inOff the offset of the ciphertext
   * @param inLen the length of the ciphertext
   * @param plaintext the output buffer for the plaintext
   * @param ptOff the offset in the plaintext buffer
   * @return true if authentication succeeded, false otherwise
   */
  boolean aesCcmDecrypt(AESKey aesKey, byte[] nonce, short nonceOff, byte[] input, short inOff, short inLen, byte[] plaintext, short ptOff) {
    short ctLen = (short) (inLen - CCM_TAG_SIZE);
    short tagOff = (short) (inOff + ctLen);

    aesCcmCtrCrypt(aesKey, nonce, nonceOff, input, inOff, ctLen, plaintext, ptOff, input, tagOff);
    aesCcmComputeMac(aesKey, nonce, nonceOff, plaintext, ptOff, ctLen);

    byte diff = 0;
    for (short i = 0; i < CCM_TAG_SIZE; i++) {
      diff |= (byte) (scratch[(short) (CCM_TAG_TMP_OFF + i)] ^ input[(short) (tagOff + i)]);
    }

    return diff == 0;
  }  

  boolean bip32IsHardened(byte[] i, short iOff) {
    return (i[iOff] & (byte) 0x80) == (byte) 0x80;
  }

  /**
   * Derives a private key according to the algorithm defined in BIP32. The BIP32 specifications define some checks
   * to be performed on the derived keys. In the very unlikely event that these checks fail this key is not considered
   * to be valid so the derived key is discarded and this method returns false.
   *
   * @param i the buffer containing the key path element (a 32-bit big endian integer)
   * @param iOff the offset in the buffer
   * @return true if successful, false otherwise
   */
  boolean bip32CKDPriv(byte[] i, short iOff, byte[] scratch, short scratchOff, byte[] data, short dataOff, byte[] output, short outOff) {
    short off = scratchOff;

    if (bip32IsHardened(i, iOff)) {
      scratch[off++] = 0;
      off = Util.arrayCopyNonAtomic(data, dataOff, scratch, off, KEY_SECRET_SIZE);
    } else {
      scratch[off++] = ((data[(short) (dataOff + KEY_SECRET_SIZE + KEY_SECRET_SIZE + KEY_PUB_SIZE - 1)] & 1) != 0 ? (byte) 0x03 : (byte) 0x02);
      off = Util.arrayCopyNonAtomic(data, (short) (dataOff + KEY_SECRET_SIZE + KEY_SECRET_SIZE + 1), scratch, off, KEY_SECRET_SIZE);
    }

    off = Util.arrayCopyNonAtomic(i, iOff, scratch, off, (short) 4);

    hmacSHA512(data, (short)(dataOff + KEY_SECRET_SIZE), KEY_SECRET_SIZE, scratch, scratchOff, (short)(off - scratchOff), output, outOff);

    if (ucmp256(output, outOff, SECP256k1.SECP256K1_R, (short) 0) >= 0) {
      return false;
    }

    bigMath.modAdd(output, outOff, KEY_SECRET_SIZE, data, dataOff, KEY_SECRET_SIZE, SECP256k1.SECP256K1_R, (short) 0, KEY_SECRET_SIZE);

    return !isZero256(output, outOff);
  }

  /**
   * Applies the algorithm for master key derivation defined by BIP32 to the binary seed provided as input.
   *
   * @param seed the binary seed
   * @param seedOff the offset of the binary seed
   * @param seedSize the size of the binary seed
   * @param masterKey the output buffer
   * @param keyOff the offset in the output buffer
   */
  void bip32MasterFromSeed(byte[] key, byte[] seed, short seedOff, short seedSize, byte[] masterKey, short keyOff) {
    hmacSHA512(key, (short) 0, (short) key.length, seed, seedOff, seedSize, masterKey, keyOff);
  }

  /**
   * Derives either a nullifier or viewing key
   * 
   * @param type the type identifier of the key to derive, either CONST_NSK or CONST_VSK
   * @param i i the buffer containing the key path element (a 32-bit big endian integer)
   * @param iOff the offset in the buffer
   * @param ssk the spending secret key
   * @param sskOff the spending secret key offset
   * @param output the output buffer
   * @param outOff the output buffer offset
   */
  void leeDeriveFromSSK(byte type, byte[] i, short iOff, byte[] ssk, short sskOff, byte[] output, short outOff) {
    sha256.update(LEE_KEY, (short) 0, (short) LEE_KEY.length);
    sha256.update(ssk, sskOff, KEY_SECRET_SIZE);
    output[outOff] = type;
    sha256.update(output, outOff, (short) 1);
    sha256.update(i, iOff, (short) 4);
    sha256.doFinal(SECP256k1.SECP256K1_A, (short) 0, (short) 19, output, outOff);
  }

  /**
   * Derives the public key from NSK
   * @param nsk
   * @param nskOff
   * @param output
   * @param outOff
   */
  void leeDerivePublicNSK(byte[] nsk, short nskOff, byte[] output, short outOff) {
    sha256.update(LEE_KEY, (short) 0, (short) LEE_KEY.length);
    sha256.update(nsk, nskOff, KEY_SECRET_SIZE);
    output[outOff] = CONST_NPK;
    sha256.update(output, outOff, (short) 1);
    sha256.doFinal(SECP256k1.SECP256K1_A, (short) 0, (short) 23, output, outOff);
  }

  /**
   * Derives child SSK, NSK, VSK and Chain. Derivation is done in place.
   *
   * @param i
   * @param iOff
   * @param nsk
   * @param nskOff
   * @param vsk
   * @param vskOff
   * @param chain
   * @param chainOff
   */
  boolean leeDeriveChild(byte[] i, short iOff, byte[] nsk, short nskOff, byte[] vsk, short vskOff, byte[] chain, short chainOff) {
    short off = Util.arrayCopyNonAtomic(LEE_SEED_PRIV, (short) 0, scratch, (short) 0, (short) LEE_SEED_PRIV.length);
    bigMath.modMul(nsk, nskOff, KEY_SECRET_SIZE, vsk, vskOff, KEY_SECRET_SIZE, SECP256k1.SECP256K1_R, (short) 0, KEY_SECRET_SIZE);
    off = Util.arrayCopyNonAtomic(nsk, nskOff, scratch, off, KEY_SECRET_SIZE);
    off = Util.arrayCopyNonAtomic(i, iOff, scratch, off, (short) 4);
    hmacSHA512(chain, chainOff, KEY_SECRET_SIZE, scratch, (short) 0, off, scratch, off);
    
    leeDeriveFromSSK(CONST_NSK, i, iOff, scratch, off, nsk, nskOff);
    leeDeriveFromSSK(CONST_VSK, i, iOff, scratch, off, vsk, vskOff);

    Util.arrayCopyNonAtomic(scratch, (short) (off + KEY_SECRET_SIZE), chain, chainOff, KEY_SECRET_SIZE);

    return !isZero256(nsk, nskOff);
  }

  /**
   * Fixes the S value of the signature as described in BIP-62 to avoid malleable signatures. It also fixes the all
   * internal TLV length fields. Returns the number of bytes by which the overall signature length changed (0 or -1).
   *
   * @param sig the signature
   * @param off the offset
   * @return the number of bytes by which the signature length changed
   */
  short fixS(byte[] sig, short off) {
    short sOff = (short) (sig[(short) (off + 3)] + (short) (off + 5));
    short ret = 0;

    if (sig[sOff] == 33) {
      Util.arrayCopyNonAtomic(sig, (short) (sOff + 2), sig, (short) (sOff + 1), (short) 32);
      sig[sOff] = 32;
      sig[(short)(off + 1)]--;
      ret = -1;
    }

    sOff++;

    if (ret == -1 || ucmp256(sig, sOff, MAX_S, (short) 0) > 0) {
      sub256(S_SUB, (short) 0, sig, sOff, sig, sOff);
    }

    return ret;
  }

  /**
   * Calculates the HMAC-SHA512 with the given key and data. Uses a software implementation which only requires SHA-512
   * to be supported on cards which do not have native HMAC-SHA512.
   *
   * @param key the HMAC key
   * @param keyOff the offset of the key
   * @param keyLen the length of the key
   * @param in the input data
   * @param inOff the offset of the input data
   * @param inLen the length of the input data
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   */
  private void hmacSHA512(byte[] key, short keyOff, short keyLen, byte[] in, short inOff, short inLen, byte[] out, short outOff) {
    if (hmacSHA512 != null) {
      hmacKey.setKey(key, keyOff, keyLen);
      hmacSHA512.init(hmacKey, Signature.MODE_SIGN);
      hmacSHA512.sign(in, inOff, inLen, out, outOff);
    } else {
      for (byte i = 0; i < 2; i++) {
        Util.arrayFillNonAtomic(hmacBlock, (short) 0, HMAC_BLOCK_SIZE_512, (i == 0 ? HMAC_IPAD : HMAC_OPAD));

        for (short j = 0; j < keyLen; j++) {
          hmacBlock[j] ^= key[(short)(keyOff + j)];
        }

        sha512.update(hmacBlock, (short) 0, HMAC_BLOCK_SIZE_512);

        if (i == 0) {
          sha512.doFinal(in, inOff, inLen, out, outOff);
        } else {
          sha512.doFinal(out, outOff, HMAC_OUT_SIZE_512, out, outOff);
        }
      }
    }
  }

  /**
   * Calculates the HMAC-SHA256 with the given key and data. Uses a software implementation which only requires SHA-256
   * to be supported on cards which do not have native HMAC-SHA256.
   *
   * @param key the HMAC key
   * @param keyOff the offset of the key
   * @param keyLen the length of the key
   * @param in the input data
   * @param inOff the offset of the input data
   * @param inLen the length of the input data
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   */
  void hmacSHA256(byte[] key, short keyOff, short keyLen, byte[] in, short inOff, short inLen, byte[] out, short outOff) {
    if (hmacSHA256 != null) {
      hmacKey.setKey(key, keyOff, keyLen);
      hmacSHA256.init(hmacKey, Signature.MODE_SIGN);
      hmacSHA256.sign(in, inOff, inLen, out, outOff);
    } else {
      for (byte i = 0; i < 2; i++) {
        Util.arrayFillNonAtomic(hmacBlock, (short) 0, HMAC_BLOCK_SIZE_256, (i == 0 ? HMAC_IPAD : HMAC_OPAD));

        for (short j = 0; j < keyLen; j++) {
          hmacBlock[j] ^= key[(short)(keyOff + j)];
        }

        sha256.update(hmacBlock, (short) 0, HMAC_BLOCK_SIZE_256);

        if (i == 0) {
          sha256.doFinal(in, inOff, inLen, out, outOff);
        } else {
          sha256.doFinal(out, outOff, HMAC_OUT_SIZE_256, out, outOff);
        }
      }
    }
  }

  /**
   * HKDF-SHA256 (Extract-then-Expand) as defined in RFC 5869 (limited to the N=1 case).
   * Extract: PRK = HMAC-SHA256(key = salt, msg = IKM)
   * Expand:  OKM = HMAC-SHA256(key = PRK, msg = info || 0x01)
   *
   * @param salt the salt (non-zero)
   * @param saltOff the offset of the salt
   * @param saltLen the length of the salt
   * @param ikm the input keying material
   * @param ikmOff the offset of the input keying material
   * @param ikmLen the length of the input keying material
   * @param info the context and application-specific information
   * @param infoOff the offset of the info
   * @param infoLen the length of the info
   * @param okm the output buffer for the output keying material
   * @param okmOff the offset in the output buffer
   */
  void hkdf(byte[] salt, short saltOff, short saltLen, byte[] ikm, short ikmOff, short ikmLen, byte[] info, short infoOff, short infoLen, byte[] okm, short okmOff) {
    // Extract: PRK = HMAC-SHA256(salt, IKM), stored in scratch
    hmacSHA256(salt, saltOff, saltLen, ikm, ikmOff, ikmLen, scratch, (short) 0);
    // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
    Util.arrayCopyNonAtomic(info, infoOff, scratch, HMAC_OUT_SIZE_256, infoLen);
    scratch[(short)(HMAC_OUT_SIZE_256 + infoLen)] = 1;
    hmacSHA256(scratch, (short) 0, HMAC_OUT_SIZE_256, scratch, HMAC_OUT_SIZE_256, (short) (infoLen + 1), okm, okmOff);
  }

  void bip0340_init_sha256(short tag) {
    sha256.update(TAGGED_PREFIXES, tag, MessageDigest.LENGTH_SHA_256);
    sha256.update(TAGGED_PREFIXES, tag, MessageDigest.LENGTH_SHA_256);
  }

  /**
   * Compares two 256-bit numbers. Returns a positive number if a > b, a negative one if a < b and 0 if a = b.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @return the comparison result
   */
  private short ucmp256(byte[] a, short aOff, byte[] b, short bOff) {
    short gt = 0;
    short eq = 1;
    
    for (short i = 0 ; i < 32; i++) {
      short l = (short)(a[(short)(aOff + i)] & 0x00ff);
      short r = (short)(b[(short)(bOff + i)] & 0x00ff);
      short d = (short)(r - l);
      short l_xor_r = (short)(l ^ r);
      short l_xor_d = (short)(l ^ d);
      short d_xored = (short)(d ^ (short)(l_xor_r & l_xor_d));

      gt |= (d_xored >>> 15) & eq;
      eq &= ((short)(l_xor_r - 1) >>> 15);
    }

    return (short) ((gt + gt + eq) - 1);
  }

  /**
   * Checks if the given 256-bit number is 0.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @return true if a is 0, false otherwise
   */
   boolean isZero256(byte[] a, short aOff) {
    byte acc = 0;

    for (short i = 0; i < 32; i++) {
      acc |= a[(short)(aOff + i)];
    }

    return acc == 0;
  }

  /**
   * A = A xor B
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   */
  void xor256(byte[] a, short aOff, byte[] b, short bOff) {
    for (short i = 0 ; i < 32; i++) {
      short l = (short)(a[(short)(aOff + i)] & 0x00ff);
      short r = (short)(b[(short)(bOff + i)] & 0x00ff);

      a[(short) (aOff + i)] = (byte)(l ^ r);
    }
  }

  /**
   * Subtraction of two 256-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the carry of the subtraction
   */
  private short sub256(byte[] a, short aOff,  byte[] b, short bOff, byte[] out, short outOff) {
    short outI = 0;

    for (short i = 31 ; i >= 0 ; i--) {
      outI = (short)  ((short)(a[(short)(aOff + i)] & 0xFF) - (short)(b[(short)(bOff + i)] & 0xFF) - outI);
      out[(short)(outOff + i)] = (byte)outI ;
      outI = (short)(((outI >> 8) != 0) ? 1 : 0);
    }

    return outI;
  }
}
