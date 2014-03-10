import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class Crypto {
  private final Cipher encipher;
  private final Cipher decipher;

  protected Crypto(Cipher encipher, Cipher decipher) {
    this.encipher = encipher;
    this.decipher = decipher;
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
