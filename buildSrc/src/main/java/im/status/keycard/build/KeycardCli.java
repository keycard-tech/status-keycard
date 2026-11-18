package im.status.keycard.build;

import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.api.logging.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Properties;

/**
 * The keycard-cli binary used to install the applets, taken from a pinned GitHub release and
 * cached in the Gradle home. Override with -Pim.status.keycard.cli.path to use a local build or
 * a mirrored copy.
 */
public class KeycardCli {
  private static final String DOWNLOAD_BASE = "https://github.com/keycard-tech/keycard-cli/releases/download/";
  private static final String PATH_PROPERTY = "im.status.keycard.cli.path";
  private static final String CACHE_DIR = "caches/keycard-cli";

  private static final Properties RELEASE = release();

  /**
   * Returns a runnable keycard-cli for the host platform, downloading it if it is not cached yet.
   *
   * @param project the project reading the override property
   * @param logger the build logger, used to report the download
   * @return the path of the binary
   */
  public static File resolve(Project project, Logger logger) {
    Object override = project.findProperty(PATH_PROPERTY);
    if (override != null) {
      File requested = project.file(override.toString());
      if (!requested.isFile()) {
        throw new GradleException(PATH_PROPERTY + " points to " + requested + ", which is not a file");
      }
      return requested;
    }

    String platform = platform();
    String tag = RELEASE.getProperty("tag");
    String expected = RELEASE.getProperty("sha256." + platform);
    if (expected == null) {
      throw new GradleException("there is no keycard-cli " + tag + " release for " + platform +
        ", set -P" + PATH_PROPERTY + " to a keycard binary");
    }

    File binary = new File(new File(cacheDir(), tag), assetName(platform));
    if (!binary.isFile() || !digest(binary).equalsIgnoreCase(expected)) {
      logger.lifecycle("Downloading keycard-cli " + tag + " (" + platform + ") to " + binary);
      download(DOWNLOAD_BASE + tag + "/" + assetName(platform), binary);

      String got = digest(binary);
      if (!got.equalsIgnoreCase(expected)) {
        binary.delete();
        throw new GradleException("the downloaded keycard-cli hashes to " + got + ", expected " + expected +
          ". Fix buildSrc/src/main/resources/keycard-cli.properties if the release is the right one.");
      }
    }

    if (!platform.startsWith("windows") && !binary.setExecutable(true, true)) {
      logger.warn("could not mark " + binary + " executable");
    }

    return binary;
  }

  private static Properties release() {
    Properties properties = new Properties();
    try (InputStream in = KeycardCli.class.getResourceAsStream("/keycard-cli.properties")) {
      if (in == null) {
        throw new IOException("keycard-cli.properties is not on the buildscript classpath");
      }
      properties.load(in);
    } catch (IOException e) {
      throw new GradleException("could not read the keycard-cli release descriptor", e);
    }
    return properties;
  }

  private static String platform() {
    String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    String osFamily;
    if (os.contains("mac") || os.contains("darwin")) {
      osFamily = "darwin";
    } else if (os.contains("win")) {
      osFamily = "windows";
    } else {
      osFamily = "linux";
    }

    String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
    String cpu;
    if (arch.equals("amd64") || arch.equals("x86_64")) {
      cpu = "amd64";
    } else if (arch.equals("aarch64") || arch.equals("arm64")) {
      cpu = "arm64";
    } else {
      throw new GradleException("there is no keycard-cli release for architecture " + arch +
        ", set -P" + PATH_PROPERTY + " to a keycard binary");
    }

    return osFamily + "-" + cpu;
  }

  private static String assetName(String platform) {
    return platform.startsWith("windows") ? "keycard-" + platform + ".exe" : "keycard-" + platform;
  }

  private static File cacheDir() {
    String gradleUserHome = System.getenv("GRADLE_USER_HOME");
    File home = gradleUserHome != null ? new File(gradleUserHome) : new File(System.getProperty("user.home"), ".gradle");
    return new File(home, CACHE_DIR);
  }

  private static void download(String url, File target) {
    File temp = new File(target.getAbsolutePath() + ".tmp");
    try {
      Files.createDirectories(target.getParentFile().toPath());

      URLConnection connection = new URL(url).openConnection();
      connection.setConnectTimeout(10000);
      connection.setReadTimeout(60000);
      connection.setRequestProperty("User-Agent", "status-keycard-gradle-build");

      try (InputStream in = connection.getInputStream(); OutputStream out = Files.newOutputStream(temp.toPath())) {
        byte[] buffer = new byte[16384];
        int read;
        while ((read = in.read(buffer)) != -1) {
          out.write(buffer, 0, read);
        }
      }

      Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      temp.delete();
      throw new GradleException("could not download " + url + " to " + target + ", set -P" + PATH_PROPERTY +
        " to a local keycard binary to build without downloading", e);
    }
  }

  private static String digest(File file) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      try (InputStream in = new FileInputStream(file)) {
        byte[] buffer = new byte[16384];
        int read;
        while ((read = in.read(buffer)) != -1) {
          sha256.update(buffer, 0, read);
        }
      }

      StringBuilder hex = new StringBuilder();
      for (byte b : sha256.digest()) {
        hex.append(String.format("%02x", b));
      }
      return hex.toString();
    } catch (IOException | NoSuchAlgorithmException e) {
      throw new GradleException("could not hash " + file, e);
    }
  }
}
