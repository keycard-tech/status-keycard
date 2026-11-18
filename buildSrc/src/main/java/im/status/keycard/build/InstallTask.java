package im.status.keycard.build;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.TaskAction;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class InstallTask extends DefaultTask {

  @TaskAction
  public void install() {
    Logger logger = getLogger();

    List<String> command = new ArrayList<>();
    command.add(KeycardCli.resolve(getProject(), logger).getAbsolutePath());
    command.add("install");
    command.add("--applet-file");
    command.add(getProject().file("build/javacard/im/status/keycard/javacard/keycard.cap").getAbsolutePath());
    command.add("--load-math");
    command.add(getProject().file("keycard-math/im/status/keycard/math/javacard/math.cap").getAbsolutePath());
    command.add("--cash-applet");
    command.add("--ndef-applet");
    command.add("--force");

    Object reader = getProject().findProperty("im.status.keycard.reader");
    if (reader != null) {
      command.add("--reader");
      command.add(reader.toString());
    }

    logger.lifecycle("Running " + String.join(" ", command));

    // GlobalPlatform keys travel in the inherited KEYCARD_GP_MAC_KEY environment variable, so
    // that they stay out of the command line above and out of the process table.
    ProcessBuilder builder = new ProcessBuilder(command);
    builder.directory(getProject().getProjectDir());
    builder.redirectErrorStream(true);

    int exitCode;
    try {
      Process process = builder.start();
      try (BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
        String line;
        while ((line = output.readLine()) != null) {
          logger.quiet(line);
        }
      }
      exitCode = process.waitFor();
    } catch (IOException e) {
      throw new GradleException("could not run " + command.get(0), e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new GradleException("keycard-cli was interrupted", e);
    }

    if (exitCode != 0) {
      throw new GradleException("keycard-cli install failed with exit code " + exitCode);
    }
  }
}
