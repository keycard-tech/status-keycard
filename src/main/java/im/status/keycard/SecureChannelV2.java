package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;

/**
 * Implements the Secure Channel Protocol v2 (AES-CCM variant).
 *
 * Provides ECDHE key exchange on secp256k1 with HKDF-SHA256 key derivation,
 * card authentication via ECDSA-SHA256 transcript signature, and AES-128-CCM
 * authenticated encryption for command/response exchange.
 */
public class SecureChannelV2 {

    // Protocol label: "sc_v2_ccm" (9 bytes)
    private static final byte[] PROTOCOL_LABEL = { 's', 'c', '_', 'v', '2', '_', 'c', 'c', 'm' };

    static final short SC_MAX_PLAIN_LENGTH = 247;
    static final short HKDF_SALT_SIZE = 32;
    static final short PUBKEY_SIZE = 65;
    static final short ECDH_SHARED_X_SIZE = 32;
    static final short OKM_SIZE = 32;
    static final short AES_KEY_SIZE = 16;
    static final short OPEN_SC_DATA_LEN = (short) (HKDF_SALT_SIZE + PUBKEY_SIZE);

    static final byte INS_OPEN_SECURE_CHANNEL = (byte) 0x10;
    static final byte INS_SECURED_APDU = (byte) 0x18;

    // Session keys
    private AESKey keyH2C;
    private AESKey keyC2H;

    // Ephemeral EC private key (transient)
    private ECPrivateKey ephemeralPriv;

    // Implicit nonce counter (13 bytes, big-endian)
    private byte[] nonceCounter;

    // Dependencies
    private Crypto crypto;
    private SECP256k1 secp256k1;

    /**
     * Creates a new SecureChannelV2 instance.
     *
     * @param crypto the Crypto utilities
     * @param secp256k1 the SECP256k1 utilities
     */
    public SecureChannelV2(Crypto crypto, SECP256k1 secp256k1) {
        this.crypto = crypto;
        this.secp256k1 = secp256k1;

        keyH2C = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        keyC2H = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);

        ephemeralPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, SECP256k1.SECP256K1_KEY_SIZE, false);
        nonceCounter = JCSystem.makeTransientByteArray(Crypto.CCM_NONCE_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    public void onSelect() {
        SECP256k1.setCurveParameters(ephemeralPriv);
    }

    /**
     * Processes the OPEN_SECURE_CHANNEL command (Phase 1: Key Exchange and Authentication).
     *
     * Generates an ephemeral key pair, computes ECDH shared secret, derives session keys
     * via HKDF-SHA256, and signs the key exchange transcript with the authentikey.
     *
     * @param apdu the APDU object
     */
    public void openSecureChannel(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        // Step 1: Validate client request
        if (buf[ISO7816.OFFSET_LC] != (byte) OPEN_SC_DATA_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (buf[ISO7816.OFFSET_P1] != 0x00 || buf[ISO7816.OFFSET_P2] != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short saltOff = ISO7816.OFFSET_CDATA;
        short clientPubOff = (short) (saltOff + HKDF_SALT_SIZE);

        if (buf[clientPubOff] != (byte) 0x04) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Step 2: Generate card ephemeral key pair
        crypto.random.generateData(crypto.scratch, (short) 0, (short) 32);
        ephemeralPriv.setS(crypto.scratch, (short) 0, (short) 32);

        // Derive card ephemeral public key: 0x04 || X(32) || Y(32)
        short responseOff = (short) (ISO7816.OFFSET_CDATA + OPEN_SC_DATA_LEN);
        secp256k1.derivePublicKey(ephemeralPriv, buf, responseOff);

        short ecdhOff = (short) (responseOff + PUBKEY_SIZE);

        try {
            // Step 3: Compute ECDH shared secret
            crypto.ecdh.init(ephemeralPriv);
            crypto.ecdh.generateSecret(buf, clientPubOff, PUBKEY_SIZE, buf, ecdhOff);
            // Shared X is at buf[ecdhOff .. ecdhOff+31] (first 32 of 64-byte XY output)
        } catch(CryptoException e) {
            // we get here when the point is not on the curve or otherwise invalid
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Step 4: HKDF-SHA256 key derivation
        short okmOff = (short) (ecdhOff + ECDH_SHARED_X_SIZE);
        crypto.hkdf(buf, saltOff, HKDF_SALT_SIZE, buf, ecdhOff, ECDH_SHARED_X_SIZE, PROTOCOL_LABEL, (short) 0, (short) PROTOCOL_LABEL.length, buf, okmOff);

        // Step 5: Set session keys (key_h2c = OKM[0..15], key_c2h = OKM[16..31])
        keyH2C.setKey(buf, okmOff);
        keyC2H.setKey(buf, (short) (okmOff + AES_KEY_SIZE));

        // Step 6: Sign transcript with authentikey
        // transcript = PROTOCOL_LABEL || hkdf_salt || client_eph_pub || card_eph_pub
        crypto.sha256.update(PROTOCOL_LABEL, (short) 0, (short) PROTOCOL_LABEL.length);
        crypto.sha256.update(buf, saltOff, HKDF_SALT_SIZE);
        crypto.sha256.update(buf, clientPubOff, PUBKEY_SIZE);
        crypto.sha256.doFinal(buf, responseOff, PUBKEY_SIZE, crypto.scratch, (short) 0);

        crypto.ecdsa.init(SharedMemory.idPrivate, Signature.MODE_SIGN);
        short sigOff = (short) (responseOff + PUBKEY_SIZE);
        short sigLen = crypto.ecdsa.signPreComputedHash(crypto.scratch, (short) 0, MessageDigest.LENGTH_SHA_256, buf, sigOff);

        // Step 7: Send response: card_eph_pub || signature
        apdu.setOutgoingAndSend(responseOff, (short) (PUBKEY_SIZE + sigLen));

        // Initialize nonce counter to zero
        Util.arrayFillNonAtomic(nonceCounter, (short) 0, Crypto.CCM_NONCE_SIZE, (byte) 0);
    }

    /**
     * Decrypts the incoming secured APDU (Phase 2).
     *
     * The plaintext inner APDU is written in-place at ISO7816.OFFSET_CLA.
     *
     * @param apduBuffer the APDU buffer
     */
    public void preprocessAPDU(byte[] apduBuffer) {
        if (!isOpen()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short totalLen = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);

        if (totalLen < (short) (5 + Crypto.CCM_TAG_SIZE)) {
            reset();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        boolean ok = crypto.aesCcmDecrypt(keyH2C, nonceCounter, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA, totalLen, apduBuffer, ISO7816.OFFSET_CLA);

        if (!ok || ((short) (totalLen - Crypto.CCM_TAG_SIZE - 5)) != (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF)) {
            reset();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Encrypts and sends the response with the inner status word (Phase 2).
     *
     * Response data must be placed at ISO7816.OFFSET_CDATA in the APDU buffer.
     * The inner SW is appended, the payload is AES-128-CCM encrypted, and sent.
     * The ISO-level status word is always 0x9000.
     *
     * @param apdu the APDU object
     * @param len the length of the response data (excluding SW)
     * @param sw the inner status word to append
     */
    public void respond(APDU apdu, short len, short sw) {
        byte[] buf = apdu.getBuffer();

        short plaintextLen = (short) (len + 2);
        Util.setShort(buf, (short) (ISO7816.OFFSET_CDATA + len), sw);

        // Encrypt in-place
        crypto.aesCcmEncrypt(keyC2H, nonceCounter, (short) 0, buf, ISO7816.OFFSET_CDATA, plaintextLen, buf, ISO7816.OFFSET_CDATA);

        if (!incrementNonce()) {
            reset();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (plaintextLen + Crypto.CCM_TAG_SIZE));
    }

    /**
     * Increments the 13-byte nonce counter as big-endian integer.
     *
     * @return true if successful, false if overflow detected
     */
    private boolean incrementNonce() {
        for (short i = Crypto.CCM_NONCE_SIZE - 1; i >= 0; i--) {
            nonceCounter[i]++;
            if (nonceCounter[i] != 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns whether a secure channel is currently established.
     *
     * @return true if the channel is open
     */
    public boolean isOpen() {
        return keyH2C.isInitialized() && keyC2H.isInitialized();
    }

    /**
     * Resets the secure channel, invalidating the current session.
     */
    public void reset() {
        keyH2C.clearKey();
        keyC2H.clearKey();
    }
}
