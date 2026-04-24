package im.status.keycard;

import im.status.keycard.applet.ApplicationStatus;
import im.status.keycard.applet.KeyPath;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import org.web3j.crypto.ECKeyPair;

import java.io.IOException;
import java.util.Arrays;

public class TestKeycardCommandSet extends KeycardCommandSet {
  private TestSecureChannelSession savedSecureChannel;
  private CardChannel savedCardChannel;

  public TestKeycardCommandSet(CardChannel apduChannel) {
    super(apduChannel);
    savedCardChannel = apduChannel;
  }

  public void setSecureChannel(TestSecureChannelSession secureChannel) {
    this.savedSecureChannel = secureChannel;
    super.setSecureChannel(secureChannel);
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

  public APDUResponse loadLEE(byte[] seed) throws IOException {
    APDUCommand loadKey = savedSecureChannel.protectedCommand(0x80, KeycardApplet.INS_LOAD_KEY, KeycardApplet.LOAD_KEY_P1_LEE, 0, seed);
    return savedSecureChannel.transmit(savedCardChannel, loadKey);
  }

  public APDUResponse signSchnorr(byte[] hash, String path) throws IOException {
    KeyPath keyPath = new KeyPath(path);
    byte[] pathData = keyPath.getData();
    byte[] data = Arrays.copyOf(hash, hash.length + pathData.length);
    System.arraycopy(pathData, 0, data, hash.length, pathData.length);
    return signWithAlgo(data, keyPath.getSource() | 1, 3);
  }

  public APDUResponse signWithAlgo(byte[] data, int p1, int p2) throws IOException {
    APDUCommand sign = savedSecureChannel.protectedCommand(0x80, KeycardApplet.INS_SIGN, p1, p2, data);
    return savedSecureChannel.transmit(savedCardChannel, sign);
  }

  public APDUResponse exportLEE(byte[] path, byte source) throws IOException {
    APDUCommand exportLee = savedSecureChannel.protectedCommand(0x80, KeycardApplet.INS_EXPORT_LEE, source, 0, path);
    return savedSecureChannel.transmit(savedCardChannel, exportLee);
  }

  public APDUResponse getChallenge(int len) throws IOException {
    APDUCommand getChallenge = savedSecureChannel.protectedCommand(0x80, KeycardApplet.INS_GET_CHALLENGE, len, 0, new byte[0]);
    return savedSecureChannel.transmit(savedCardChannel, getChallenge);
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
}
