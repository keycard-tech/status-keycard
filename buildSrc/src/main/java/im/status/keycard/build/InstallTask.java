package im.status.keycard.build;

import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.globalplatform.LoadCallback;
import im.status.keycard.io.APDUException;
import org.bouncycastle.util.encoders.Hex;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.TaskAction;

import javax.smartcardio.*;
import java.io.FileInputStream;
import java.io.IOException;

import apdu4j.pcsc.TerminalManager;

public class InstallTask extends DefaultTask {

  @TaskAction
  public void install() {
    Logger logger = getLogger();

    TerminalFactory tf = TerminalManager.getTerminalFactory();
    CardTerminal cardTerminal = null;

    try {
      for (CardTerminal t : tf.terminals().list()) {
        if (t.isCardPresent()) {
          cardTerminal = t;
          break;
        }
      }
    } catch(CardException e) {
      throw new GradleException("Error listing card terminals", e);
    }

    if (cardTerminal == null) {
      throw new GradleException("No available PC/SC terminal");
    }

    Card apduCard;

    try {
      apduCard = cardTerminal.connect("*");
    } catch(CardException e) {
      throw new GradleException("Couldn't connect to the card", e);
    }

    logger.info("Connected to " + cardTerminal.getName());
    PCSCCardChannel sdkChannel = new PCSCCardChannel(apduCard.getBasicChannel());
    TestGlobalPlatformCommandSet cmdSet = new TestGlobalPlatformCommandSet(sdkChannel);

    try {
      logger.info("Selecting the ISD");
      cmdSet.select().checkOK();
      logger.info("Opening a SecureChannel");
      cmdSet.openSecureChannel(false);
      logger.info("Deleting the old instances and package (if present)");
      cmdSet.deleteKeycardInstancesAndPackage();
      logger.info("Loading the math package");
      byte[] mathPackageAid = Hex.decode("A0000008040002");
      try {
        cmdSet.loadPackage(mathPackageAid, new FileInputStream(this.getProject().file("keycard-math/im/status/keycard/math/javacard/math.cap")));
      } catch(APDUException e) {
        logger.info("Math package already loaded");
      }
      logger.info("Loading the keycard package");
      cmdSet.loadKeycardPackage(new FileInputStream(this.getProject().file("build/javacard/im/status/keycard/javacard/keycard.cap")), new LoadCallback() {
        @Override
        public void blockLoaded(int loadedBlock, int blockCount) {
          logger.info("Loaded block " + loadedBlock + "/" + blockCount);
        }
      });
      logger.info("Installing the Keycard Applet");
      cmdSet.installKeycardApplet().checkOK();
      logger.info("Installing the NDEF Applet");
      cmdSet.installNDEFApplet(new byte[0]).checkOK();
      logger.info("Installing the Cash Applet");
      cmdSet.installCashApplet().checkOK();
      logger.info("Installing the Identifier Applet");
      cmdSet.installIdentApplet().checkOK();
    } catch (IOException e) {
      throw new GradleException("I/O error", e);
    } catch (APDUException e) {
      throw new GradleException(e.getMessage(), e);
    }
  }
}
