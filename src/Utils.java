import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utils is *meant* to hold a bunch of handy static methods but it's ended up
 * being a place to catch all the hundreds of crypto exceptions thrown by Java.
 * The idea is to store boilerplate/uninteresting code.
 */
public final class Utils {

  private static final int KEYSIZE_RSA = 2048;
  private static final String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";
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

  /** Generate the Hmac/SHA-1 digest for the given data using the given key. */
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

  /**
   * Generate the keyed MAC for the given data with the given key and algorithm
   * specified by the key.
   */
  public static byte[] mac(byte[] data, SecretKeySpec key) {
    byte[] signature = null;
    try {
      Mac mac = Mac.getInstance(key.getAlgorithm(), "BC");
      mac.init(key);
      signature = mac.doFinal(data);
    } catch (NoSuchAlgorithmException e) {
      System.err.println(key.getAlgorithm() + " algorithm not found!");
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

  /** Generate random string for session keys. */
  public static String generateChallengeValue(Random random) {
    return new BigInteger(130, random).toString(32);
  }

  /** Load a KeyStore from a Jave Key Store (.jks) file of the given name. */
  public static KeyStore loadJKSKeyStore(String filename, String password) {
    KeyStore keyStore = null;
    try {
      keyStore = KeyStore.getInstance("JKS");
    } catch (KeyStoreException e) {
      System.err.println("Error getting KeyStore instance!");
      e.printStackTrace();
    }
    String path = "keys/" + filename;
    InputStream in = null;
    try {
      in = new FileInputStream(path);
      keyStore.load(in, password.toCharArray());
    } catch (FileNotFoundException e) {
      System.err.println("File not found at " + path);
      e.printStackTrace();
    } catch (IOException e) {
      System.err.println("Error reading file at " + path);
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      System.err.println("Algorithm not found!");
      e.printStackTrace();
    } catch (CertificateException e) {
      System.err.println("Certificate problem!");
      e.printStackTrace();
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (IOException ignored) {
        }
      }
    }

    return keyStore;
  }

  /** Load a Certificate from the given KeyStore with the given alias. */
  public static Certificate loadCertificateFromKeyStore(KeyStore keyStore, String alias) {
    KeyStore.Entry entry = loadEntryFromKeyStore(keyStore, alias);
    if (entry instanceof KeyStore.TrustedCertificateEntry) {
      return ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
    }
    return null;
  }

  /** Load a PrivateKey from the given KeyStore with the given alias. */
  public static PrivateKey loadPrivateKeyFromKeyStore(KeyStore keyStore, String alias,
        String password) {
    KeyStore.Entry entry = loadEntryFromKeyStore(keyStore, alias, password);
    if (entry instanceof KeyStore.PrivateKeyEntry) {
      return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
    }
    return null;
  }

  /**
   * Load an entry from the given KeyStore with the given alias. The entry must
   * not have any password protection.
   */
  public static KeyStore.Entry loadEntryFromKeyStore(KeyStore keyStore, String alias,
        String password) {
    KeyStore.Entry entry = null;
    try {
      entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
    } catch (NoSuchAlgorithmException e) {
      System.err.println("Algorithm not found!");
      e.printStackTrace();
    } catch (KeyStoreException e) {
      System.err.println("Error getting KeyStore instance!");
      e.printStackTrace();
    } catch (UnrecoverableEntryException e) {
      System.err.println("Could not recover key entry!");
      e.printStackTrace();
    }
    return entry;
  }

  /**
   * Load an entry from the given KeyStore with the given alias and password.
   */
  public static KeyStore.Entry loadEntryFromKeyStore(KeyStore keyStore, String alias) {
    KeyStore.Entry entry = null;
    try {
      entry = keyStore.getEntry(alias, null);
    } catch (NoSuchAlgorithmException e) {
      System.err.println("Algorithm not found!");
      e.printStackTrace();
    } catch (KeyStoreException e) {
      System.err.println("Error getting KeyStore instance!");
      e.printStackTrace();
    } catch (UnrecoverableEntryException e) {
      System.err.println("Could not recover key entry!");
      e.printStackTrace();
    }
    return entry;
  }

  /**
   * Get a Cipher with the default RSA implementation, initialized with the
   * given mode and certificate.
   */
  public static Cipher getRsaCipherInstance(int mode, Certificate cert) {
    Cipher cipher = getCipherInstance(ALGORITHM_RSA);
    if (cipher != null) {
      try {
        cipher.init(mode, cert);
      } catch (InvalidKeyException e) {
        System.err.println("Invalid key!");
        e.printStackTrace();
      }
    }
    return cipher;
  }

  /**
   * Get a Cipher with the default RSA implementation, initialized with the
   * given mode and key.
   */
  public static Cipher getRsaCipherInstance(int mode, Key key) {
    Cipher cipher = getCipherInstance(ALGORITHM_RSA);
    if (cipher != null) {
      try {
        cipher.init(mode, key);
      } catch (InvalidKeyException e) {
        System.err.println("Invalid key!");
        e.printStackTrace();
      }
    }
    return cipher;
  }

  /** Get a Cipher for the given algorithm using the BouncyCastle provider. */
  public static Cipher getCipherInstance(String algorithm) {
    Cipher cipher = null;
    try {
      cipher = Cipher.getInstance(algorithm, "BC");
    } catch (NoSuchAlgorithmException e) {
      System.err.println(algorithm + " algorithm not found!");
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      System.err.println("BouncyCastle provider not found!");
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      System.err.println(algorithm + " padding not found!");
      e.printStackTrace();
    }
    return cipher;
  }

  /**
   * Encrypts a Base64 encoded message using the given cipher. Cipher must be in
   * encryption mode.
   */
  public static String encrypt(Cipher cipher, String message) {
    String output = null;
    try {
      byte[] data = cipher.doFinal(message.getBytes());
      output = new String(Base64.encodeBase64(data));
    } catch (IllegalBlockSizeException e) {
      System.err.println("Illegal block size!");
      e.printStackTrace();
    } catch (BadPaddingException e) {
      System.err.println("Bad padding!");
      e.printStackTrace();
    }
    return output;
  }

  /**
   * Decrypts a Base64 encoded message using the given cipher. Cipher must be in
   * decryption mode.
   */
  public static String decrypt(Cipher cipher, String message) {
    String output = null;
    try {
      byte[] data = cipher.doFinal(Base64.decodeBase64(message.getBytes()));
      output = new String(data);
    } catch (IllegalBlockSizeException e) {
      System.err.println("Illegal block size!");
      e.printStackTrace();
    } catch (BadPaddingException e) {
      System.err.println("Bad padding!");
      e.printStackTrace();
    }
    return output;
  }

}
