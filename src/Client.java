import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import javax.crypto.Cipher;
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

  private final SecureRandom random = new SecureRandom();
  private final AuthManager authManager = new AuthManager();

  private KeyStore keyStore;
  private Cipher rsaCrypto;

  public Client(KeyStore keyStore) {
    this.keyStore = keyStore;

    // Testing...
    Certificate serverCert = Utils.loadCertificateFromKeyStore(keyStore, "server");
    Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, serverCert);
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


      authManager.setSessionKey(sessionKeyString);
    } else {
      System.out.println("Server auth failed!");
    }
  }

  public static void main(String[] args) throws Exception {
    Client client = new Client(Utils.loadJKSKeystore("client.jks", "fishtitty"));
    client.performHandshake();
  }

}
