import java.io.IOException;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.fluent.Content;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

public class Client {

  private static final Log LOG = LogFactory.getLog(Client.class);

  private static final String BASE_URL = "http://localhost:8080";

  /**
   * Regex for valid file. (ID + 3 numbers)(1) + hyphen + (1 or more arbitrary
   * characters)(2). 1 -> the ID, 2 -> the message details.
   */
  private static final Pattern FILE_PATTERN = Pattern.compile("^(?<id>ID\\d{3})-(?<details>.+)$");

  /** Regex for files sent/received to/from server. */
  private static final Pattern PACKAGED_FILE_PATTERN =
      Pattern.compile("^(?<id>ID\\d{3})(?<encrypteddetails>.+)(?<hash>.{28})$"); //" sublime_text2

  private static final String HTTP_AUTH_PATH = "/auth";
  private static final String HTTP_FILE_PATH = "/files";
  private static final String HTTP_METHOD = "POST";

  private final SecureRandom random = new SecureRandom();

  private Cipher authEncipher;
  private Cipher authDecipher;

  private Cipher fileEncipher;
  private Cipher fileDecipher;

  private Cipher sessionEncipher;
  private Cipher sessionDecipher;

  private Cipher signingEncipher;
  private Cipher signingDecipher;

  private File docRoot;

  public Client(KeyStore asymmetricKeyStore, KeyStore symmetricKeyStore, String path) {
    initRsaCrypto(asymmetricKeyStore);
    initAesCrypto(symmetricKeyStore);

    docRoot = new File(path);
    if (!docRoot.exists()) {
      docRoot.mkdirs();
    }
  }

  private void initRsaCrypto(KeyStore keyStore) {
    Certificate serverCert = Utils.loadCertificateFromKeyStore(keyStore, "server");
    authEncipher = Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, serverCert);
    signingDecipher = Utils.getRsaCipherInstance(Cipher.DECRYPT_MODE, serverCert);

    PrivateKey clientKey = Utils.loadPrivateKeyFromKeyStore(keyStore, "client", "fishtitty");
    authDecipher = Utils.getRsaCipherInstance(Cipher.DECRYPT_MODE, clientKey);
    signingEncipher = Utils.getRsaCipherInstance(Cipher.ENCRYPT_MODE, clientKey);
  }

  private void initAesCrypto(KeyStore keyStore) {
    SecretKey clientSecret = Utils.loadSecretKeyFromKeyStore(keyStore, "clientsecret", "fishtitty");
    fileEncipher = Utils.getAesCipherInstance(Cipher.ENCRYPT_MODE, clientSecret);
    fileDecipher = Utils.getAesCipherInstance(Cipher.DECRYPT_MODE, clientSecret);
  }

  ///////////////
  // HANDSHAKE //
  ///////////////

  public void performHandshake() throws ClientProtocolException, IOException {
    // Generate random token
    String clientChallenge = Utils.generateChallengeValue(random);
    LOG.debug("Client challenge: " + clientChallenge);

    // Build the request string
    String request = rsaEncryptForm(Form.form()
        .add("action", "initiate")
        .add("client_challenge", clientChallenge));

    // Initiate connection with server, get new challenge
    HttpResponse response = post(BASE_URL + HTTP_AUTH_PATH, request);
    int responseCode = response.getStatusLine().getStatusCode();
    LOG.info("Server responded with status code " + responseCode);
    if (responseCode != HttpStatus.SC_OK) {
      LOG.error("Server rejected initial handshake request.");
      LOG.error("Server response message: " + EntityUtils.toString(response.getEntity()));
      return;
    }

    // Decrypt and parse the response from the server
    String serverResponse = rsaDecrypt(EntityUtils.toString(response.getEntity()));
    Map<String, String> params = HttpUtils.parseQueryParams(serverResponse);
    String clientChallengeResponse = params.get("client_challenge");

    // Check the client challenge matches
    LOG.debug("Server response to client challenge: " + clientChallengeResponse);
    if (!clientChallenge.equals(clientChallengeResponse)) {
      LOG.error("Server response did not match client challenge!");
      LOG.error("Handshake failed!");
      return;
    }

    String serverChallenge = params.get("server_challenge");
    LOG.debug("Server challenge: " + serverChallenge);

    // Respond to the server, confirming the challenge response
    request = rsaEncryptForm(Form.form()
        .add("action", "confirm")
        .add("server_challenge", serverChallenge));

    response = post(BASE_URL + HTTP_AUTH_PATH, request);
    responseCode = response.getStatusLine().getStatusCode();
    LOG.info("Server responded with status code " + responseCode);
    if (responseCode != HttpStatus.SC_OK) {
      LOG.error("Server did not accept response to challenge!");
      LOG.error("Handshake failed!");
      return;
    }

    byte[] sessionKey = Utils.calculateSessionKey(clientChallenge, serverChallenge);
    initSessionCipher(sessionKey);
  }

  private void initSessionCipher(byte[] sessionKey) {
    sessionEncipher = Utils.getAesCipherInstance(Cipher.ENCRYPT_MODE, sessionKey);
    sessionDecipher = Utils.getAesCipherInstance(Cipher.DECRYPT_MODE, sessionKey);
  }

  private String rsaEncryptForm(Form form) {
    List<NameValuePair> params = form.build();
    String formString = URLEncodedUtils.format(params, "UTF-8");
    return Utils.encrypt(authEncipher, formString);
  }

  private String rsaDecrypt(String message) {
    return Utils.decrypt(authDecipher, message);
  }

  ///////////////////////
  // FILE SEND/RECEIVE //
  ///////////////////////

  /** Send the file with the given filename. */
  public void sendFile(String filename) throws IOException, FileNotFoundException {
    if (sessionEncipher == null || sessionDecipher == null) {
      LOG.warn("Session cipher not initialized, cannot fetch file.");
      return;
    }

    // Read file contents
    File file = new File(docRoot, filename);
    if (!file.exists()) {
      LOG.warn("File not found at " + file.getPath());
      return;
    }

    List<String> fileLines = Utils.readFileLines(file);

    // Package file for sending
    StringBuilder sb = new StringBuilder();
    for (int i = 0, n = fileLines.size(); i < n; i++) {
      String line = fileLines.get(i);
      String packagedLine = packageLine(line);
      if (packagedLine == null) {
        LOG.warn("File line " + i + " is malformed.");
      } else {
        sb.append(line);
        sb.append('\n');
      }
    }

    String packagedFile = sb.toString();

    // Construct the form for the request
    List<NameValuePair> params = Form.form()
        .add("action", "put")
        .add("file", packagedFile)
        .build();

    String request = signAndEncryptFileRequest(params);

    // Upload file to server
    HttpResponse response = post(BASE_URL + HTTP_FILE_PATH, request);
    int responseCode = response.getStatusLine().getStatusCode();
    LOG.info("Server responded with status code " + responseCode);
    if (responseCode == HttpStatus.SC_OK) {
      LOG.info("Server accepted file!");
    } else {
      LOG.error("Server rejected request.");
    }
  }

  /** Fetch the file with the given filename. */
  public void fetchFile(String id, String filename) throws IOException {
    if (sessionEncipher == null || sessionDecipher == null) {
      LOG.warn("Session cipher not initialized, cannot fetch file.");
      return;
    }

    // Specify the request
    List<NameValuePair> params = Form.form()
        .add("action", "get")
        .add("id", id)
        .build();

    // Sign and encrypt
    String request = signAndEncryptFileRequest(params);

    // Perform the request (upload the file)
    HttpResponse response = post(BASE_URL + HTTP_FILE_PATH, request);

    int responseCode = response.getStatusLine().getStatusCode();
    LOG.info("Server responded with status code " + responseCode);
    if (responseCode != HttpStatus.SC_OK) {
      LOG.error("Server rejected request!");
      return;
    }

    String decryptedResponse =
        Utils.decrypt(sessionDecipher, EntityUtils.toString(response.getEntity()));

    // Parse the response data
    Map<String, String> responseParams = HttpUtils.parseQueryParams(decryptedResponse);

    // Grab the signature and decrypt it
    String signature = responseParams.remove("signature");
    if (signature == null) {
      LOG.warn("Request not signed! Rejecting request...");
      return;
    }
    String digest = Utils.decrypt(signingDecipher, signature);

    // Calculate the expected signature
    String stringToSign = HttpUtils.buildParamsString(responseParams);
    String calculatedSignature = Utils.sha1Hash(stringToSign);
    if (!calculatedSignature.equals(digest)) {
      LOG.error("Signature mismatch! Couldn't ensure integrity of file.");
      return;
    }

    // Decrypt the contents of the server response
    String packagedFile = responseParams.get("file");
    LOG.info("Packaged file: " + packagedFile);

    // Unpackage the file and save it
    String unpackagedFile = unpackageFile(packagedFile);
    LOG.debug("Unpackaged file: " + unpackagedFile);
    if (unpackagedFile != null) {
      File file = new File(docRoot, filename);
      Utils.writeFile(file, unpackagedFile);
    } else {
      LOG.error("Failed to unpack file!");
    }
  }

  private String signAndEncryptFileRequest(List<NameValuePair> params) {
    // Sign the request
    String requestString = HttpUtils.buildParamsString(params);
    String stringToSign = HttpUtils.stringToSign(HTTP_METHOD, HTTP_FILE_PATH, requestString);
    String digest = Utils.sha1Hash(stringToSign);
    String signature = Utils.encrypt(signingEncipher, digest);
    params.add(new BasicNameValuePair("signature", signature));

    // Encrypt the request
    String signedRequestString = HttpUtils.buildParamsString(params);
    String encryptedAndSignedRequest = Utils.encrypt(sessionEncipher, signedRequestString);

    return encryptedAndSignedRequest;
  }

  /**
   * Package the file to be sent.
   * F = ID||Encrypted[DETAILS]||hash[ID||DETAILS]
   */
  private String packageLine(String line) {
    Matcher matcher = FILE_PATTERN.matcher(line);
    if (!matcher.matches()) {
      return null;
    }

    // Get ID and DETAILS parts
    String id = matcher.group("id");
    String details = matcher.group("details");

    // Build up the "encrypted" message
    String encryptedDetails = Utils.encrypt(fileEncipher, details);
    String fileHash = Utils.sha1Hash(id + details);
    String message = id + encryptedDetails + fileHash;
    return message;
  }

  /**
   * Unpackage a file from the form sent to the server.
   * F = ID||"-"||DETAILS
   */
  private String unpackageLine(String packagedLine) {
    Matcher matcher = PACKAGED_FILE_PATTERN.matcher(packagedLine);
    if (!matcher.matches()) {
      LOG.error("Received file did not match format!");
      return null;
    }

    // Get the various parts of the packaged file
    String id = matcher.group("id");
    String encryptedDetails = matcher.group("encrypteddetails");
    String hash = matcher.group("hash");

    // Decrypt the details
    String details = aesDecrypt(encryptedDetails);

    // Calculate the hash for ID||DETAILS and compare to received hash
    String calculatedHash = Utils.sha1Hash(id + details);
    if (!hash.equals(calculatedHash)) {
      LOG.error("Calculated hash didn't match provided hash!");
      return null;
    }

    // Build up file into original form
    return id + "-" + details;
  }

  private String aesDecrypt(String message) {
    return Utils.decrypt(fileDecipher, message);
  }

  private HttpResponse post(String url, String form) throws IOException, ClientProtocolException {
    return Request.Post(url).bodyString(form, ContentType.TEXT_PLAIN).execute().returnResponse();
  }

  public static void main(String[] args) throws Exception {
    KeyStore jksKeyStore = Utils.loadKeyStore("JKS", "client.jks", "fishtitty");
    KeyStore jckKeyStore = Utils.loadKeyStore("JCEKS", "clientsecret.jck", "fishtitty");
    Client client = new Client(jksKeyStore, jckKeyStore, "./clientfiles");

    //
    client.performHandshake();
    client.sendFile("ID007.txt");
    client.fetchFile("ID007", "ID007(1).txt");

    /*String packagedFile = client.packageFile("ID007-Bond,James,High Priority");
    System.out.println("Packaged file: " + packagedFile);
    String unpackagedFile = client.unpackageFile(packagedFile);
    System.out.println("Unpackaged file: " + unpackagedFile);*/
  }

}
