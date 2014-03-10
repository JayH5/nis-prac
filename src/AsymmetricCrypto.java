import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricCrypto extends Crypto {
  private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
  private static final String PROVIDER = "BC";

  protected AsymmetricCrypto(Cipher encipher, Cipher decipher) {
    super(encipher, decipher);
  }

  /** Get a new instance of this crypto. Such exception. */
  public static AsymmetricCrypto getInstance(Key encryptKey, Key decryptKey)
      throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
      InvalidKeyException {
    Cipher encipher = Cipher.getInstance(ALGORITHM, PROVIDER);
    encipher.init(Cipher.ENCRYPT_MODE, encryptKey);

    Cipher decipher = Cipher.getInstance(ALGORITHM, PROVIDER);
    decipher.init(Cipher.DECRYPT_MODE, decryptKey);

    return new AsymmetricCrypto(encipher, decipher);
  }

}
