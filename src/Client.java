import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) {
    // TODO
  }
}
