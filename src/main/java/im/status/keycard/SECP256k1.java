package im.status.keycard;

import im.status.keycard.math.BigNumberMath;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.*;

/**
 * Utility methods to work with the SECP256k1 curve.
 */
public class SECP256k1 {
  static final byte SECP256K1_FP[] = {
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
  };
  static final byte SECP256K1_A[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
  };
  static final byte SECP256K1_B[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07
  };
  static final byte SECP256K1_G[] = {
      (byte)0x04,
      (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
      (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
      (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
      (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
      (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
      (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
      (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
      (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
  };
  static final byte SECP256K1_R[] = {
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
      (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
      (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
  };

  static final byte SECP256K1_K = (byte)0x01;

  static final short SECP256K1_KEY_SIZE = 256;

  private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

  private static final short SCHNORR_SK_OFF = (short) 0;
  private static final short SCHNORR_PUB_OFF = (short) 32;
  private static final short SCHNORR_K_OFF = (short) 97;
  private static final short SCHNORR_OUT_SIG_OFF = (short) 34;

  static final byte SIGN_ECDSA = 0x00;
  static final byte SIGN_ED25519 = 0x01;
  static final byte SIGN_BLS12_381 = 0x02;
  static final byte SIGN_BIP340_SCHNORR = 0x03;

  static final byte TLV_RAW_SIGNATURE = (byte) 0x80;

  private KeyAgreement ecPointMultiplier;
  ECPrivateKey tmpECPrivateKey;

  /**
   * Allocates objects needed by this class. Must be invoked during the applet installation exactly 1 time.
   */
  SECP256k1() {
    this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
    this.tmpECPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256K1_KEY_SIZE, false);
    setCurveParameters(tmpECPrivateKey);
  }

  /**
   * Sets the SECP256k1 curve parameters to the given ECKey (public or private).
   *
   * @param key the key where the curve parameters must be set
   */
  static void setCurveParameters(ECKey key) {
    key.setA(SECP256K1_A, (short) 0x00, (short) SECP256K1_A.length);
    key.setB(SECP256K1_B, (short) 0x00, (short) SECP256K1_B.length);
    key.setFieldFP(SECP256K1_FP, (short) 0x00, (short) SECP256K1_FP.length);
    key.setG(SECP256K1_G, (short) 0x00, (short) SECP256K1_G.length);
    key.setR(SECP256K1_R, (short) 0x00, (short) SECP256K1_R.length);
    key.setK(SECP256K1_K);
  }

  /**
   * Derives the public key from the given private key and outputs it in the pubOut buffer. This is done by multiplying
   * the private key by the G point of the curve.
   *
   * @param privateKey the private key
   * @param pubOut the output buffer for the public key
   * @param pubOff the offset in pubOut
   * @return the length of the public key
   */
  short derivePublicKey(ECPrivateKey privateKey, byte[] pubOut, short pubOff) {
    return multiplyPoint(privateKey, SECP256K1_G, (short) 0, (short) SECP256K1_G.length, pubOut, pubOff);
  }

  /**
   * Derives the public key from the given private key and outputs it in the pubOut buffer. This is done by multiplying
   * the private key by the G point of the curve.
   *
   * @param privateKey the private key
   * @param pubOut the output buffer for the public key
   * @param pubOff the offset in pubOut
   * @return the length of the public key
   */
  short derivePublicKey(byte[] privateKey, short privOff, byte[] pubOut, short pubOff) {
    tmpECPrivateKey.setS(privateKey, privOff, (short)(SECP256K1_KEY_SIZE/8));
    return derivePublicKey(tmpECPrivateKey, pubOut, pubOff);
  }

  /**
   * Multiplies a scalar in the form of a private key by the given point. Internally uses a special version of EC-DH
   * supported since JavaCard 3.0.5 which outputs both X and Y in their uncompressed form.
   *
   * @param privateKey the scalar in a private key object
   * @param point the point to multiply
   * @param pointOff the offset of the point
   * @param pointLen the length of the point
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the length of the data written in the out buffer
   */
  short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out, short outOff) {
    ecPointMultiplier.init(privateKey);
    return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
  }

  void schnorrPrivPub(Crypto crypto, byte[] key, short keyOff) {
    derivePublicKey(key, keyOff, crypto.scratch, SCHNORR_PUB_OFF);
    if ((crypto.scratch[(short)(SCHNORR_PUB_OFF + 64)] & (byte) 0x01) == (byte) 1) {
      Util.arrayFillNonAtomic(crypto.scratch, (short) (SCHNORR_PUB_OFF + 33), (short) 32, (byte) 0);
      BigNumberMath.modSub(crypto.scratch, (short) (SCHNORR_PUB_OFF + 33), (short) 32, key, keyOff, (short) 32, SECP256K1_R, (short) 0, (short) 32);
      Util.arrayCopyNonAtomic(crypto.scratch, (short) (SCHNORR_PUB_OFF + 33), key, keyOff, (short) 32);
    }
  }

  short schnorrSign(Crypto crypto, ECPrivateKey key, byte[] hash, short hashOff, byte[] out, short outOff) {
    key.getS(crypto.scratch, SCHNORR_SK_OFF);
    schnorrPrivPub(crypto, crypto.scratch, SCHNORR_SK_OFF);
    Util.arrayCopyNonAtomic(crypto.scratch, (short) (SCHNORR_PUB_OFF + 1), out, outOff, (short) 32);

    while (true) {
      crypto.random.generateData(crypto.scratch, SCHNORR_K_OFF, (short) 32);
      crypto.bip0340_init_sha256(Crypto.BIP0340_AUX);
      crypto.sha256.doFinal(crypto.scratch, SCHNORR_K_OFF, (short) 32, crypto.scratch, SCHNORR_K_OFF);
      crypto.xor256(crypto.scratch, SCHNORR_K_OFF, crypto.scratch, SCHNORR_SK_OFF);
      crypto.bip0340_init_sha256(Crypto.BIP0340_NONCE);
      crypto.sha256.update(crypto.scratch, SCHNORR_K_OFF, (short) 32);
      crypto.sha256.update(out, outOff, (short) 32);
      crypto.sha256.doFinal(hash, hashOff, (short) 32, crypto.scratch, SCHNORR_K_OFF);
      BigNumberMath.modRed(crypto.scratch, SCHNORR_K_OFF, (short) 32, SECP256K1_R, (short) 0, (short) 32);
      if (!crypto.isZero256(crypto.scratch, SCHNORR_K_OFF)) {
        break;
      }
    }

    schnorrPrivPub(crypto, crypto.scratch, SCHNORR_K_OFF);
    crypto.bip0340_init_sha256(Crypto.BIP0340_CHALLENGE);
    crypto.sha256.update(crypto.scratch, (short) (SCHNORR_PUB_OFF + 1), (short) 32);
    crypto.sha256.update(out, outOff, (short) 32);
    crypto.sha256.doFinal(hash, hashOff, (short) 32, out, (short) (outOff + SCHNORR_OUT_SIG_OFF));
    BigNumberMath.modRed(out, (short) (outOff + SCHNORR_OUT_SIG_OFF), (short) 32, SECP256K1_R, (short) 0, (short) 32);

    out[outOff] = TLV_RAW_SIGNATURE;
    out[(short)(outOff + 1)] = (byte) 64;
    Util.arrayCopyNonAtomic(crypto.scratch, (short) (SCHNORR_PUB_OFF + 1), out, (short) (outOff + 2), (short) 32);

    BigNumberMath.modMul(out, (short) (outOff + SCHNORR_OUT_SIG_OFF), (short) 32, crypto.scratch, SCHNORR_SK_OFF, (short) 32, SECP256K1_R, (short) 0, (short) 32);
    BigNumberMath.modAdd(out, (short) (outOff + SCHNORR_OUT_SIG_OFF), (short) 32, crypto.scratch, SCHNORR_K_OFF, (short) 32, SECP256K1_R, (short) 0, (short) 32);

    return (short) 66;
  }

  short ecdsaSign(Crypto crypto, ECPrivateKey key, byte[] hash, short hashOff, byte[] out, short outOff) {
    crypto.ecdsa.init(key, Signature.MODE_SIGN);

    short sigLen = crypto.ecdsa.signPreComputedHash(hash, hashOff, MessageDigest.LENGTH_SHA_256, out, outOff);
    sigLen += crypto.fixS(out, outOff);

    return sigLen;
  }

  short signHash(byte algo, Crypto crypto, ECPrivateKey key, byte[] hash, short hashOff, byte[] out, short outOff) {
    switch(algo) {
      case SIGN_ECDSA:
        return ecdsaSign(crypto, key, hash, hashOff, out, outOff);
      case SIGN_BIP340_SCHNORR:
        return schnorrSign(crypto, key, hash, hashOff, out, outOff);
      case SIGN_ED25519:
      case SIGN_BLS12_381:
      default:
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return -1;
    }
  }
}
