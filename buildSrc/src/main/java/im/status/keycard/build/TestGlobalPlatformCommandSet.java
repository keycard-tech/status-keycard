package im.status.keycard.build;

import im.status.keycard.globalplatform.GlobalPlatformCommandSet;
import im.status.keycard.globalplatform.Load;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;

import java.io.IOException;
import java.io.InputStream;

public class TestGlobalPlatformCommandSet extends GlobalPlatformCommandSet {

  public TestGlobalPlatformCommandSet(im.status.keycard.io.CardChannel apduChannel) {
    super(apduChannel);
  }

  public void loadPackage(byte[] packageAid, InputStream in) throws IOException, APDUException {
    APDUResponse resp = installForLoad(packageAid).checkOK();

    Load load = new Load(in);

    byte[] block;

    while((block = load.nextDataBlock()) != null) {
      load(block, (load.getCount() - 1), load.hasMore()).checkOK();
    }
  }
}
