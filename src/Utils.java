import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public final class Utils {

  private static final int KEYSIZE_RSA = 2048;
  private static final int KEYSIZE_AES = 256;

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

  public static byte[] hmacSha1(byte[] data, byte[] key) {
    byte[] signature = null;
    try {
      Mac mac = Mac.getInstance("HmacSHA1", "BC");
      mac.init(new SecretKeySpec(key, "HmacSHA1"));
      signature = mac.doFinal(data);
    } catch (NoSuchAlgorithmException e) {
      System.err.println("HmacSHA-1 algorithm not found!");
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      System.err.println("BouncyCastle provider not found!");
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      System.err.println("Invalid key!");
      e.printStackTrace();
    }
    return signature;
  }

  /** Generate an RSA public/private key pair. */
  public static KeyPair generateRSAKeyPair() {
    KeyPair keyPair = null;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
      generator.initialize(KEYSIZE_RSA);
      keyPair = generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      System.err.println("RSA algorithm not found!");
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      System.err.println("BouncyCastle provider not found!");
      e.printStackTrace();
    }
    return keyPair;
  }

  /** Generate a secret key suitable for AES. */
  public static SecretKey generateAESKeyPair() {
    SecretKey key = null;
    try {
      KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
      generator.init(KEYSIZE_AES);
      key = generator.generateKey();
    } catch (NoSuchAlgorithmException e) {
      System.err.println("AES algorithm not found!");
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      System.err.println("BouncyCastle provider not found!");
      e.printStackTrace();
    }
    return key;
  }

}
