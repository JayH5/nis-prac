import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class SymmetricCrypto extends Crypto {
  private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String PROVIDER = "BC";

  protected SymmetricCrypto(Cipher encipher, Cipher decipher) {
    super(encipher, decipher);
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

}
