import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Server {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) {
    // TODO
  }
}
