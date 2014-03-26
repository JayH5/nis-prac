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

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.ProtocolException;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;
import org.apache.http.client.utils.URLEncodedUtils;

public class AuthorizationHandler implements HttpRequestHandler {

    private final AuthManager authManager;
    private final SecureRandom random = new SecureRandom();

    // The session key for auth that is not yet confirmed
    private String pendingAuth;

    private Cipher decipher;
    private Cipher encipher;

    public AuthorizationHandler(KeyStore keyStore, AuthManager authManager) {
      this.authManager = authManager;
      initCrypto(keyStore);
    }

    private void initCrypto(KeyStore keyStore) {
      Certificate clientCert = Utils.loadCertificateFromKeyStore(keyStore, "client");
      encipher = Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, clientCert);

      PrivateKey serverKey = Utils.loadPrivateKeyFromKeyStore(keyStore, "server", "tittyfish");
      decipher = Utils.getRsaCipherInstance(Cipher.DECRYPT_MODE, serverKey);
    }

    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context)
        throws HttpException, IOException {
      String method = HttpUtils.parseMethod(request);
      if (!method.equals("POST")) {
        throw new MethodNotSupportedException(method + " method not supported");
      }
      String target = request.getRequestLine().getUri();

      URI uri = null;
      try {
        uri = new URI(target);
      } catch (URISyntaxException e) {
        throw new ProtocolException(target + " uri not supported");
      }

      System.out.println("target = " + target);

      // Get auth post form data
      String entityContent = HttpUtils.parseStringContent(request);

      String decryptedEntity = decrypt(entityContent);

      System.out.println("Entity: " + decryptedEntity);

      // Find signature among parameters
      Map<String, String> queryParams = HttpUtils.parseQueryParams(decryptedEntity);
      String action = queryParams.get("action");
      String token = queryParams.get("token");

      if (action != null && token != null) {
        if ("initiate".equals(action)) {
          // Take token, repond with new random number
          String responseToken = Utils.generateChallengeValue(random);
          pendingAuth = token + responseToken;
          response.setStatusCode(HttpStatus.SC_OK);
          StringEntity entity = new StringEntity(encrypt(pendingAuth));
          response.setEntity(entity);
        } else if ("confirm".equals(action)) {
          if (pendingAuth != null && pendingAuth.equals(token)) {
            pendingAuth += token;
            updateSessionKey();
            response.setStatusCode(HttpStatus.SC_OK);
            StringEntity entity = new StringEntity(encrypt("Oh hai, client!"));
            response.setEntity(entity);
          } else {
            HttpUtils.forbidden(response);
          }
        }
      } else {
        HttpUtils.forbidden(response);
      }
    }

    private String encrypt(String message) {
      return Utils.encrypt(encipher, message);
    }

    private String decrypt(String message) {
      return Utils.decrypt(decipher, message);
    }

    private void updateSessionKey() {
      if (pendingAuth != null) {
        authManager.setSessionKey(pendingAuth);
        pendingAuth = null;
      }
    }

  }