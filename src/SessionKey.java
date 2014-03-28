import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class SessionKey {

  private SecretKeySpec key;
  private Date validFrom;
  private Date validUntil;

  public SessionKey() {
  }

  // TODO: Proper validfrom/validuntil
  public void setSessionKeyData(byte[] data) {
    Calendar cal = Calendar.getInstance();
    Date validFrom = cal.getTime();
    cal.add(Calendar.HOUR_OF_DAY, 1);
    Date validUntil = cal.getTime();
    setSessionKey(data, validFrom, validUntil);
  }

  public void setSessionKey(byte[] key, Date validFrom, Date validUntil) {
    this.key = new SecretKeySpec(key, "AES");
    this.validFrom = validFrom;
    this.validUntil = validUntil;
  }

  public SecretKeySpec getKeySpec() {
    return key;
  }

  public boolean isValid() {
    if (key == null) {
      return false;
    }

    Date now = new Date();
    return now.after(validFrom) && now.before(validUntil);
  }

}
