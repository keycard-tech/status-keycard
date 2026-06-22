package im.status.keycard;

import im.status.keycard.applet.ApplicationStatus;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import org.web3j.crypto.ECKeyPair;

import java.io.IOException;

public class TestKeycardCommandSet extends KeycardCommandSet {
  private im.status.keycard.io.CardChannel channel;

  public TestKeycardCommandSet(im.status.keycard.io.CardChannel apduChannel, byte[] caKey) {
    super(apduChannel, caKey);
    this.channel = apduChannel;
  }

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format, includes the public key and no chain code, meaning that
   * the card will not be able to do further key derivation. This is needed when the argument is an EC keypair from
   * the web3j package instead of the regular Java ones. Used by the test which actually submits the transaction to
   * the network.
   *
   * @param ecKeyPair a key pair
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse loadKey(ECKeyPair ecKeyPair) throws IOException {
    byte[] publicKey = ecKeyPair.getPublicKey().toByteArray();
    byte[] privateKey = ecKeyPair.getPrivateKey().toByteArray();

    int pubLen = publicKey.length;
    int pubOff = 0;

    if(publicKey[0] == 0x00) {
      pubOff++;
      pubLen--;
    }

    byte[] ansiPublic = new byte[pubLen + 1];
    ansiPublic[0] = 0x04;
    System.arraycopy(publicKey, pubOff, ansiPublic, 1, pubLen);

    return loadKey(ansiPublic, privateKey, null);
  }

  /**
   * Sends a GET STATUS APDU to retrieve the APPLICATION STATUS template and reads the byte indicating key initialization
   * status
   *
   * @return whether the master key is present or not
   * @throws IOException communication error
   */
  public boolean getKeyInitializationStatus() throws IOException {
    APDUResponse resp = getStatus(GET_STATUS_P1_APPLICATION);
    return new ApplicationStatus(resp.getData()).hasMasterKey();
  }

  /**
   * Sends an OPEN_SECURE_CHANNEL APDU with the given 32-byte salt and 65-byte uncompressed client public key.
   * The APDU is sent as INS=0x10, CLA=0x80, P1=0x00, P2=0x00, Lc=97.
   */
  public APDUResponse openSecureChannel(byte[] salt, byte[] clientPublicKey) throws IOException {
    byte[] data = new byte[(short) (salt.length + clientPublicKey.length)];
    System.arraycopy(salt, 0, data, 0, salt.length);
    System.arraycopy(clientPublicKey, 0, data, salt.length, clientPublicKey.length);
    return channel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, data));
  }

  /**
   * Sends an OPEN_SECURE_CHANNEL APDU with a random 32-byte salt and the given uncompressed client public key.
   */
  public APDUResponse openSecureChannel(byte[] clientPublicKey) throws IOException {
    byte[] salt = new byte[32];
    for (int i = 0; i < salt.length; i++) {
      salt[i] = (byte) (i + 1);
    }
    return openSecureChannel(salt, clientPublicKey);
  }

  /**
   * Sends an OPEN_SECURE_CHANNEL APDU with a random 32-byte salt and a freshly generated secp256k1 key pair.
   * Returns the raw card response.
   */
  public APDUResponse openSecureChannel() throws Exception {
    java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC", "BC");
    org.bouncycastle.jce.spec.ECParameterSpec ecSpec =
        org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
    g.initialize(ecSpec);
    java.security.KeyPair kp = g.generateKeyPair();

    byte[] publicKey = ((org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic()).getQ().getEncoded(true);
    return openSecureChannel(publicKey);
  }

  /**
   * Sends a raw GET DATA APDU with the given P1 (data type) and P2 (offset) parameters.
   * This is needed because the SDK does not support segmented GET DATA for NDEF.
   *
   * @param p1 the data type (e.g. STORE_DATA_P1_NDEF = 0x01)
   * @param p2 the byte offset into the data
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse getDataRaw(byte p1, byte p2) throws IOException {
    return this.getSecureChannel().transmit(channel, this.getSecureChannel().protectedCommand(0x80, KeycardApplet.INS_GET_DATA, p1, p2, new byte[0]));
  }
}
