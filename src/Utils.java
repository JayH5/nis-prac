import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;

public final class Utils {
  /** Read a file into a list of Strings. */
  public static List<String> readFileLines(String path) throws IOException, FileNotFoundException {
    List<String> lines = new ArrayList<String>();
    BufferedReader br = new BufferedReader(new FileReader(path));
    try {
      for (String line; (line = br.readLine()) != null;) {
        lines.add(line);
      }
    } finally {
      br.close();
    }
    return lines;
  }

  /** Calculate the SHA-1 hash of some data. */
  public static byte[] sha1Hash(byte[] data) {
      byte[] hash = null;
      try {
        MessageDigest digest = MessageDigest.getInstance("SHA-1", "BC");
        digest.update(data);
        hash = digest.digest();
      } catch (NoSuchAlgorithmException e) {
        System.err.println("SHA-1 algorithm not found!");
        e.printStackTrace();
      } catch (NoSuchProviderException e) {
        System.err.println("BouncyCastle provider not found!");
        e.printStackTrace();
      }
      return hash;
  }

  /** Calculate the hex-string representation of the SHA-1 hash of a String. */
  public static String sha1Hash(String data) {
    byte[] hash = sha1Hash(data.getBytes());
    if (hash == null) {
      return null;
    }

    return Hex.toHexString(hash);
  }

  /** Generate an RSA public/private key pair. Default initialization. */
  public static KeyPair generateRSAKeyPair() {
    KeyPair keyPair = null;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
      keyPair = generator.generateKeyPair(); // Default settings for now...
    } catch (NoSuchAlgorithmException e) {
      System.err.println("SHA-1 algorithm not found!");
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      System.err.println("BouncyCastle provider not found!");
      e.printStackTrace();
    }
    return keyPair;
  }
}
