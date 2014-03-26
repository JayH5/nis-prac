import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class AuthManager {

  private static final String KEY_ALGORITHM = "HmacSHA1";

  private SessionKey sessionKey;

  public AuthManager() {
  }

  public void setSessionKey(String key) {
    SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
    Calendar cal = Calendar.getInstance();
    Date validFrom = cal.getTime();
    cal.add(Calendar.HOUR_OF_DAY, 1);
    Date validUntil = cal.getTime();
    sessionKey = new SessionKey(secretKey, validFrom, validUntil);
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
