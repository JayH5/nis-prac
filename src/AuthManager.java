import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class AuthManager {

  private SessionKey sessionKey;

  public AuthManager() {
  }

  public void setSessionKey(SessionKey key) {
    sessionKey = key;
  }

  public boolean isValidSignature(String signature, byte[] data) {
    if (sessionKey == null || !sessionKey.isValid()) {
      return false;
    }

    byte[] expectedSignature = Utils.mac(data, sessionKey.key);
    return Hex.toHexString(expectedSignature).equals(signature);
  }

  public static class SessionKey {
    private final SecretKeySpec key;
    private final Date validFrom;
    private final Date validUntil;

    public SessionKey(SecretKeySpec key, Date validFrom, Date validUntil) {
      this.key = key;
      this.validFrom = validFrom;
      this.validUntil = validUntil;
    }

    public boolean isValid() {
      Date now = new Date();
      return now.after(validFrom) && now.before(validUntil);
    }
  }
}
