import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SymmetricCrypto {
  private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String PROVIDER = "BC";

  private final Cipher encipher;
  private final Cipher decipher;

  protected SymmetricCrypto(Cipher encipher, Cipher decipher) {
    this.encipher = encipher;
    this.decipher = decipher;
  }

  /** Get a new instance of this crypto. Such exception. */
  public static SymmetricCrypto getInstance(Key key)
      throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
      InvalidKeyException {
    Cipher encipher = Cipher.getInstance(ALGORITHM, PROVIDER);
    encipher.init(Cipher.ENCRYPT_MODE, key);

    Cipher decipher = Cipher.getInstance(ALGORITHM, PROVIDER);
    decipher.init(Cipher.DECRYPT_MODE, key);

    return new SymmetricCrypto(encipher, decipher);
  }

  /** Encrypt some data. */
  public byte[] encrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException {
    // TODO: Provide multi-part encryption
    return encipher.doFinal(data);
  }

  /** Decrypt some data. */
  public byte[] decrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException {
    // TODO: Provide multi-part decryption
    return decipher.doFinal(data);
  }

}
