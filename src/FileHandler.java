import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Form;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;

public class FileHandler implements HttpRequestHandler {

  private static final Log LOG = LogFactory.getLog(FileHandler.class);
  private static final Pattern ID_PATTERN = Pattern.compile("^(?<id>ID\\d{3}).+$");

  private final SessionKey sessionKey;
  private final File docRoot;

  private Cipher signingDecipher;
  private Cipher signingEncipher;

  public FileHandler(PrivateKey serverKey, Certificate clientCert, SessionKey sessionKey,
        File docRoot) {
    signingEncipher = Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, serverKey);
    signingDecipher = Utils.getRsaCipherInstance(Cipher.DECRYPT_MODE, clientCert);

    this.sessionKey = sessionKey;
    this.docRoot = docRoot;
  }

  @Override
  public void handle(HttpRequest request, HttpResponse response, HttpContext context)
      throws HttpException, IOException {
    String method = HttpUtils.parseMethod(request);
    if (!method.equals("POST")) {
      throw new MethodNotSupportedException(method + " method not supported");
    }
    String target = request.getRequestLine().getUri();
    LOG.debug("Incoming request with target: " + target);

    // Check if the session key is valid before continuing...
    if (!sessionKey.isValid()) {
      LOG.warn("Session Key invalid! Cannot proceed with file request.");
      HttpUtils.forbidden(response);
      return;
    }

    String entityContent = HttpUtils.parseStringContent(request);
    LOG.info("Incoming entity content: " + entityContent);

    // Decrypt the request
    Cipher decipher = Utils.getAesCipherInstance(Cipher.DECRYPT_MODE, sessionKey.getKeySpec());
    String decryptedRequest = Utils.decrypt(decipher, entityContent);
    LOG.debug("Decrypted request: " + decryptedRequest);

    // Parse the request
    Map<String, String> params = HttpUtils.parseQueryParams(decryptedRequest);

    // Grab the signature and decrypt it
    String signature = params.remove("signature");
    if (signature == null) {
      LOG.warn("Request not signed! Rejecting request...");
      HttpUtils.forbidden(response);
      return;
    }
    String digest = Utils.decrypt(signingDecipher, signature);

    // Calculate the expected signature
    String stringToSign =
        HttpUtils.stringToSign(method, target, HttpUtils.buildParamsString(params));
    String calculatedSignature = Utils.sha1Hash(stringToSign);

    // Compare to received signature
    if (!calculatedSignature.equals(digest)) {
      LOG.warn("Signature mismatch! Rejecting request...");
      HttpUtils.forbidden(response);
      return;
    }

    // Respond to the request
    String action = params.get("action");
    if ("get".equals(action)) {
      Cipher encipher = Utils.getAesCipherInstance(Cipher.ENCRYPT_MODE, sessionKey.getKeySpec());
      serveFile(params.get("id"), response, encipher);
    } else if ("put".equals(action)) {
      saveFile(params.get("file"), response);
    } else {
      LOG.warn("Invalid action in request: " + action);
      HttpUtils.forbidden(response);
    }
  }

  private void saveFile(String content, HttpResponse response) throws IOException {
    // Parse the ID so we know where to save
    Matcher matcher = ID_PATTERN.matcher(content);
    if (!matcher.matches()) { // Couldn't find ID
      LOG.warn("ID couldn't be extracted from message!");
      HttpUtils.forbidden(response);
      return;
    }

    String id = matcher.group("id");

    File file = new File(docRoot, id);
    Utils.writeFile(file, content);
    response.setStatusCode(HttpStatus.SC_OK);
    LOG.info("File with id " + id + " was succesfully saved.");
  }

  private void serveFile(String id, HttpResponse response, Cipher sessionEncipher)
      throws IOException {
    LOG.debug("Serving file with id: " + id);
    File file = new File(docRoot, id);
    if (!file.exists()) {
      LOG.warn("File with " + id + " does not exist!");
      HttpUtils.notFound(response);
      return;
    }

    // Read the file
    String fileContents = Utils.readFile(file);
    System.out.println("File contents: " + fileContents);
    // Form a response
    List<NameValuePair> params = Form.form()
        .add("file", fileContents)
        .build();

    // Sign, encrypt and send off
    String responseString = signAndEncryptResponse(params, sessionEncipher);
    response.setStatusCode(HttpStatus.SC_OK);
    response.setEntity(new StringEntity(responseString, ContentType.create("text/plain")));

    LOG.info("Sent file with id " + id);
  }

  private String signAndEncryptResponse(List<NameValuePair> params, Cipher sessionEncipher) {
    // Sign the response
    String responseString = HttpUtils.buildParamsString(params);
    String digest = Utils.sha1Hash(responseString);
    String signature = Utils.encrypt(signingEncipher, digest);
    params.add(new BasicNameValuePair("signature", signature));

    // Encrypt the response
    String signedResponseString = HttpUtils.buildParamsString(params);
    String encryptedAndSignedResponse = Utils.encrypt(sessionEncipher, signedResponseString);

    return encryptedAndSignedResponse;
  }

}