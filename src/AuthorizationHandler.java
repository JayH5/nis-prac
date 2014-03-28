import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import javax.crypto.Cipher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.ProtocolException;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.client.fluent.Form;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;
import org.apache.http.client.utils.URLEncodedUtils;

public class AuthorizationHandler implements HttpRequestHandler {

  private static final Log LOG = LogFactory.getLog(AuthorizationHandler.class);

  private final SecureRandom random = new SecureRandom();

  // The session key for auth that is not yet confirmed
  private String clientChallenge;
  private String serverChallenge;

  private Cipher decipher;
  private Cipher encipher;

  private final SessionKey sessionKey;

  public AuthorizationHandler(PrivateKey serverKey, Certificate clientCert, SessionKey sessionKey) {
    encipher = Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, clientCert);
    decipher = Utils.getRsaCipherInstance(Cipher.DECRYPT_MODE, serverKey);

    this.sessionKey = sessionKey;
  }

  @Override
  public void handle(HttpRequest request, HttpResponse response, HttpContext context)
      throws HttpException, IOException {
    String method = HttpUtils.parseMethod(request);
    if (!method.equals("POST")) {
      throw new MethodNotSupportedException(method + " method not supported");
    }

    // Get auth post form data
    String entityContent = HttpUtils.parseStringContent(request);

    String decryptedEntity = decrypt(entityContent);

    LOG.debug("Incoming auth request: " + decryptedEntity);

    // Find signature among parameters
    Map<String, String> queryParams = HttpUtils.parseQueryParams(decryptedEntity);
    String action = queryParams.get("action");

    if ("initiate".equals(action)) {
      String challenge = queryParams.get("client_challenge");
      LOG.debug("Client challenge " + challenge);

      if (challenge == null || !Utils.isValidChallenge(challenge)) {
        LOG.warn("Invalid challenge from client!");
        LOG.warn("Cannot continue with handshake.");
        HttpUtils.forbidden(response);
        return;
      }
      clientChallenge = challenge;

      // Respond with client challenge and own challenge
      serverChallenge = Utils.generateChallengeValue(random);
      List<NameValuePair> params = Form.form()
          .add("client_challenge", clientChallenge)
          .add("server_challenge", serverChallenge)
          .build();

      String responseContent = HttpUtils.buildParamsString(params);

      // Respond with code 200, encrypt client and server challenges
      response.setStatusCode(HttpStatus.SC_OK);
      StringEntity entity = new StringEntity(encrypt(responseContent));
      response.setEntity(entity);
    } else if ("confirm".equals(action)) {
      String challenge = queryParams.get("server_challenge");
      LOG.debug("Client response to challenge " + challenge);

      // Check that challenge matches
      if (serverChallenge == null || !serverChallenge.equals(challenge)) {
        LOG.warn("Handshake not initialized or challenge mismatch!");
        LOG.warn("Cannot continue with handshake.");
        HttpUtils.forbidden(response);

        // Reset challenges
        clientChallenge = null;
        serverChallenge = null;
        return;
      }

      // Respond A-OK TODO: Send validFrom/validUntil dates
      response.setStatusCode(HttpStatus.SC_OK);
      byte[] sessionKeyData = Utils.calculateSessionKey(clientChallenge, serverChallenge);
      sessionKey.setSessionKeyData(sessionKeyData);
    } else {
      LOG.warn("Invalid auth action from client: " + action);
      LOG.warn("Cannot continue with handshake.");
      HttpUtils.forbidden(response);
    }
  }

  private String encrypt(String message) {
    return Utils.encrypt(encipher, message);
  }

  private String decrypt(String message) {
    return Utils.decrypt(decipher, message);
  }

}