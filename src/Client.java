import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
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

  private static final String BASE_URL = "http://localhost:8080";

  /**
   * Regex for valid file. (ID + 3 numbers)(1) + hyphen + (1 or more arbitrary
   * characters)(2). 1 -> the ID, 2 -> the message details.
   */
  private static final Pattern FILE_PATTERN = Pattern.compile("^(?<id>ID\\d{3})-(?<details>.+)$");

  private final SecureRandom random = new SecureRandom();
  private final AuthManager authManager = new AuthManager();

  private Cipher rsaEncipher;
  private Cipher rsaDecipher;
  private Cipher aesEncipher;
  private Cipher aesDecipher;

  public Client(KeyStore asymmetricKeyStore, KeyStore symmetricKeyStore) {
    initRsaCrypto(asymmetricKeyStore);
    initAesCrypto(symmetricKeyStore);
  }

  private void initRsaCrypto(KeyStore keyStore) {
    Certificate serverCert = Utils.loadCertificateFromKeyStore(keyStore, "server");
    rsaEncipher = Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, serverCert);

    PrivateKey clientKey = Utils.loadPrivateKeyFromKeyStore(keyStore, "client", "fishtitty");
    rsaDecipher = Utils.getRsaCipherInstance(Cipher.DECRYPT_MODE, clientKey);
  }

  private void initAesCrypto(KeyStore keyStore) {
    SecretKey clientSecret = Utils.loadSecretKeyFromKeyStore(keyStore, "clientsecret", "fishtitty");
    aesEncipher = Utils.getAesCipherInstance(Cipher.ENCRYPT_MODE, clientSecret);
    aesDecipher = Utils.getAesCipherInstance(Cipher.DECRYPT_MODE, clientSecret);
  }

  public void performHandshake() throws ClientProtocolException, IOException {
    // Generate random token
    String clientChallenge = Utils.generateChallengeValue(random);
    System.out.println("Client token: " + clientChallenge);

    // Build the request string
    String request = rsaEncryptForm(Form.form()
        .add("action", "initiate")
        .add("token", clientChallenge));

    // Initiate connection with server, get new challenge
    String response = post(BASE_URL + "/auth", request);

    // Decrypt server response
    String serverChallenge = rsaDecrypt(response);

    // Check if the server challenge responded with our challenge
    if (serverChallenge.startsWith(clientChallenge)) {
      System.out.println("Server response successful!");

      // Respond to the server, confirming the challenge response
      request = rsaEncryptForm(Form.form()
          .add("action", "confirm")
          .add("token", serverChallenge));

      // yay auth worked
      response = post(BASE_URL + "/auth", request);

      String decryptedResponse = rsaDecrypt(response);

      authManager.setSessionKey(decryptedResponse);
    } else {
      System.out.println("Server auth failed!");
    }
  }

  private String rsaEncryptForm(Form form) {
    List<NameValuePair> params = form.build();
    String formString = URLEncodedUtils.format(params, "UTF-8");
    return Utils.encrypt(rsaEncipher, formString);
  }

  private String rsaDecrypt(String message) {
    return Utils.decrypt(rsaDecipher, message);
  }

  /** Encrypt message and append digest. */
  private String prepareFile(String file) {
    Matcher matcher = FILE_PATTERN.matcher(file);
    if (!matcher.matches()) {
      return null;
    }

    // Get ID and DETAILS parts
    String id = matcher.group("id");
    String details = matcher.group("details");

    // Build up the "encrypted" message
    String encryptedDetails = Utils.encrypt(aesEncipher, details);
    String fileHash = Utils.sha1Hash(id + details);
    String message = id + encryptedDetails + fileHash;
    return message;
  }

  private String aesDecrypt(String message) {
    return Utils.decrypt(aesDecipher, message);
  }

  private String post(String url, String form) throws IOException, ClientProtocolException {
    return Request.Post(url).bodyString(form, ContentType.TEXT_PLAIN)
        .execute().returnContent().asString();
  }

  public static void main(String[] args) throws Exception {
    KeyStore jksKeyStore = Utils.loadKeyStore("JKS", "client.jks", "fishtitty");
    KeyStore jckKeyStore = Utils.loadKeyStore("JCEKS", "clientsecret.jck", "fishtitty");
    Client client = new Client(jksKeyStore, jckKeyStore);
    client.performHandshake();
  }

}
