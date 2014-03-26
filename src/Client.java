import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.fluent.Content;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;

public class Client {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String BASE_URL = "http://localhost:8080";

  private final SecureRandom random = new SecureRandom();
  private final AuthManager authManager = new AuthManager();

  private Cipher encipher;
  private Cipher decipher;

  public Client(KeyStore keyStore) {
    initCrypto(keyStore);
  }

  private void initCrypto(KeyStore keyStore) {
    Certificate clientCert = Utils.loadCertificateFromKeyStore(keyStore, "server");
    encipher = Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, clientCert);

    PrivateKey serverKey = Utils.loadPrivateKeyFromKeyStore(keyStore, "client", "fishtitty");
    decipher = Utils.getRsaCipherInstance(Cipher.DECRYPT_MODE, serverKey);
  }

  public void performHandshake() throws ClientProtocolException, IOException {
    // Generate random token
    String clientChallenge = Utils.generateChallengeValue(random);
    System.out.println("Client token: " + clientChallenge);

    // Build the request string
    String request = encryptForm(Form.form()
        .add("action", "initiate")
        .add("token", clientChallenge));

    // Initiate connection with server, get new challenge
    String response = post(BASE_URL + "/auth", request);

    // Decrypt server response
    String serverChallenge = decrypt(response);

    // Check if the server challenge responded with our challenge
    if (serverChallenge.startsWith(clientChallenge)) {
      System.out.println("Server response successful!");

      // Respond to the server, confirming the challenge response
      request = encryptForm(Form.form()
          .add("action", "confirm")
          .add("token", serverChallenge));

      // yay auth worked
      response = post(BASE_URL + "/auth", request);

      String decryptedResponse = decrypt(response);

      authManager.setSessionKey(decryptedResponse);
    } else {
      System.out.println("Server auth failed!");
    }
  }

  private String encryptForm(Form form) {
    List<NameValuePair> params = form.build();
    String formString = URLEncodedUtils.format(params, "UTF-8");
    System.out.println("Encrypting form data: " + formString);
    String encryptedForm = Utils.encrypt(encipher, formString);
    System.out.println("Encrypted data: " + encryptedForm);
    return encryptedForm;
  }

  private String decrypt(String message) {
    System.out.println("Decrypting: " + message);
    return Utils.decrypt(decipher, message);
  }

  private String post(String url, String form) throws IOException, ClientProtocolException {
    return Request.Post(url).bodyString(form, ContentType.TEXT_PLAIN)
        .execute().returnContent().asString();
  }

  public static void main(String[] args) throws Exception {
    Client client = new Client(Utils.loadJKSKeyStore("client.jks", "fishtitty"));
    client.performHandshake();
  }

}
