import java.io.IOException;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.fluent.Content;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;

public class Client {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String BASE_URL = "http://localhost:8080";

  public static void main(String[] args) throws Exception {
    Client client = new Client();
    client.performHandshake();
  }

  private final SecureRandom random = new SecureRandom();
  private final AuthManager authManager = new AuthManager();

  public Client() {
  }

  public void performHandshake() throws ClientProtocolException, IOException {
    // Generate random token
    String token = Utils.generateSessionKey(random);
    System.out.println("Client token: " + token);

    // Initiate connection with server, get new challenge
    String resp = Request.Post(BASE_URL + "/auth")
        .bodyForm(Form.form().add("action", "initiate").add("token", token).build())
        .execute().returnContent().asString();

    String sessionKeyString = resp;

    System.out.println("Server response 1: " + resp);
    if (resp.startsWith(token)) {
      // yay auth worked
      resp = Request.Post(BASE_URL + "/auth")
          .bodyForm(Form.form().add("action", "confirm").add("token", sessionKeyString).build())
          .execute().returnContent().asString();

      System.out.println("Server response 2: " + resp);


      saveSessionKey(sessionKeyString);
    } else {
      System.out.println("Server auth failed!");
    }
  }

  private void saveSessionKey(String key) {
    SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
    Calendar cal = Calendar.getInstance();
    Date validFrom = cal.getTime();
    cal.add(Calendar.HOUR_OF_DAY, 1);
    Date validUntil = cal.getTime();
    AuthManager.SessionKey sessionKey =
        new AuthManager.SessionKey(secretKey, validFrom, validUntil);
    authManager.setSessionKey(sessionKey);
  }
}
