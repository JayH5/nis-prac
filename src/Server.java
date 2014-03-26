import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Locale;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.ConnectionClosedException;
import org.apache.http.HttpConnectionFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpServerConnection;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.ProtocolException;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.DefaultBHttpServerConnectionFactory;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpProcessorBuilder;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.apache.http.protocol.UriHttpRequestHandlerMapper;
import org.apache.http.util.EntityUtils;
import org.apache.http.client.utils.URLEncodedUtils;

public class Server {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final int PORT = 8080;

  public static void main(String[] args) throws Exception {
    Server server = new Server(Utils.loadJKSKeyStore("server.jks", "tittyfish"), "files/");
    server.listen(PORT);
  }

  // Document root directory
  private final String docRoot;
  private final HttpService httpService;

  public Server(KeyStore keyStore, String docRoot) {
    this.docRoot = docRoot;

    // Set up the HTTP protocol processor
    HttpProcessor httpproc = HttpProcessorBuilder.create()
        .add(new ResponseDate())
        .add(new ResponseServer("Test/1.1"))
        .add(new ResponseContent())
        .add(new ResponseConnControl()).build();

    AuthManager authManager = new AuthManager();

    // Set up request handlers
    UriHttpRequestHandlerMapper reqistry = new UriHttpRequestHandlerMapper();
    reqistry.register("/auth", new AuthorizationHandler(keyStore, authManager));
    reqistry.register("/files", new FileHandler(authManager, docRoot));
    reqistry.register("*", new DefaultHandler());

    // Set up the HTTP service
    httpService = new HttpService(httpproc, reqistry);
  }

  public void listen(int port) throws IOException {
    Thread t = new RequestListenerThread(PORT, httpService);
    t.setDaemon(false);
    t.start();
  }

  static class FileHandler implements HttpRequestHandler {

    private final AuthManager authManager;
    private final String docRoot;

    public FileHandler(AuthManager authManager, String docRoot) {
      this.authManager = authManager;
      this.docRoot = docRoot;
    }

    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context)
        throws HttpException, IOException {
      String method = request.getRequestLine().getMethod().toUpperCase(Locale.ENGLISH);
      if (!method.equals("GET") && !method.equals("POST")) {
        throw new MethodNotSupportedException(method + " method not supported");
      }
      String target = request.getRequestLine().getUri();

      // Parse action into a URI
      URI uri = null;
      try {
        uri = new URI(target);
      } catch (URISyntaxException e) {
        throw new ProtocolException(target + " uri not supported");
      }

      // Parse the params
      List<NameValuePair> params = URLEncodedUtils.parse(uri, "UTF-8");

      // Find signature among parameters
      String signature = null;
      for (NameValuePair param : params) {
        if ("signature".equals(param.getName())) {
          signature = param.getValue();
          break;
        }
      }

      System.out.println("Signature= " + signature);

      byte[] entityContent = null;
      if (method.equals("POST") && request instanceof HttpEntityEnclosingRequest) {
        // Get file data
        HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
        entityContent = EntityUtils.toByteArray(entity);
        System.out.println("Incoming entity content (bytes): " + entityContent.length);
      }

      if (authManager.isValidSignature(signature, entityContent)) {
        System.out.println("Signature verified!");
      } else {
        System.out.println("Signature check failed!");
        forbidden(response);
        return;
      }

      File file = new File(this.docRoot, uri.getPath());
      if (!file.exists()) {

        response.setStatusCode(HttpStatus.SC_NOT_FOUND);
        StringEntity entity = new StringEntity(
            "<html><body><h1>File" + file.getPath() +
            " not found</h1></body></html>",
            ContentType.create("text/html", "UTF-8"));
        response.setEntity(entity);
        System.out.println("File " + file.getPath() + " not found");

      } else if (!file.canRead() || file.isDirectory()) {

        response.setStatusCode(HttpStatus.SC_FORBIDDEN);
        StringEntity entity = new StringEntity(
            "<html><body><h1>Access denied</h1></body></html>",
            ContentType.create("text/html", "UTF-8"));
        response.setEntity(entity);
        System.out.println("Cannot read file " + file.getPath());

      } else {

        response.setStatusCode(HttpStatus.SC_OK);
        FileEntity body = new FileEntity(file, ContentType.create("text/html", (Charset) null));
        response.setEntity(body);
        System.out.println("Serving file " + file.getPath());
      }
    }

  }

  static class AuthorizationHandler implements HttpRequestHandler {

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
      String method = request.getRequestLine().getMethod().toUpperCase(Locale.ENGLISH);
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
      String entityContent = null;
      if (request instanceof HttpEntityEnclosingRequest) {
        HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
        entityContent = EntityUtils.toString(entity);
        System.out.println("Incoming entity content (bytes): " + entityContent.length());
      }

      String decryptedEntity = decrypt(entityContent);

      System.out.println("Entity: " + decryptedEntity);

      // Find signature among parameters
      List<NameValuePair> formData =
          URLEncodedUtils.parse(decryptedEntity, Charset.forName("UTF-8"));
      String action = null;
      String token = null;
      for (NameValuePair param : formData) {
        if ("action".equals(param.getName())) {
          action = param.getValue();
        } else if ("token".equals(param.getName())) {
          token = param.getValue();
        }
      }

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
            forbidden(response);
          }
        }
      } else {
        forbidden(response);
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

  private static void forbidden(HttpResponse response) {
    response.setStatusCode(HttpStatus.SC_FORBIDDEN);
    StringEntity entity = new StringEntity(
        "<html><body><h1>403 FORBIDDEN</h1></body></html>",
        ContentType.create("text/html", "UTF-8"));
    response.setEntity(entity);
  }

  /** Default handler for all unknown requests. Just returns 404 */
  static class DefaultHandler implements HttpRequestHandler {
    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context) {
      String method = request.getRequestLine().getMethod().toUpperCase(Locale.ENGLISH);
      String target = request.getRequestLine().getUri();

      System.out.println("Unknown request: " + method + " " + target);

      // Respond with a 404
      response.setStatusCode(HttpStatus.SC_NOT_FOUND);
      StringEntity entity = new StringEntity(
          "<html><body><h1>404 NOT FOUND</h1></body></html>",
          ContentType.create("text/html", "UTF-8"));
      response.setEntity(entity);
    }
  }

  static class RequestListenerThread extends Thread {

    private final HttpConnectionFactory<DefaultBHttpServerConnection> connFactory;
    private final ServerSocket serversocket;
    private final HttpService httpService;

    public RequestListenerThread(int port, HttpService httpService) throws IOException {
      this.connFactory = DefaultBHttpServerConnectionFactory.INSTANCE;
      this.serversocket = new ServerSocket(port);
      this.httpService = httpService;
    }

    @Override
    public void run() {
      System.out.println("Listening on port " + this.serversocket.getLocalPort());
      while (!Thread.interrupted()) {
        try {
          // Set up HTTP connection
          Socket socket = this.serversocket.accept();
          System.out.println("Incoming connection from " + socket.getInetAddress());
          HttpServerConnection conn = this.connFactory.createConnection(socket);

          // Start worker thread
          Thread t = new WorkerThread(this.httpService, conn);
          t.setDaemon(true);
          t.start();
        } catch (InterruptedIOException ex) {
          break;
        } catch (IOException e) {
          System.err.println("I/O error initialising connection thread: "
                  + e.getMessage());
          break;
        }
      }
    }
  }

  static class WorkerThread extends Thread {

    private final HttpService httpservice;
    private final HttpServerConnection conn;

    public WorkerThread(HttpService httpservice, HttpServerConnection conn) {
      super();
      this.httpservice = httpservice;
      this.conn = conn;
    }

    @Override
    public void run() {
      System.out.println("New connection thread");
      HttpContext context = new BasicHttpContext(null);
      try {
        while (!Thread.interrupted() && this.conn.isOpen()) {
          this.httpservice.handleRequest(this.conn, context);
        }
      } catch (ConnectionClosedException ex) {
        System.err.println("Client closed connection");
      } catch (IOException ex) {
        System.err.println("I/O error: " + ex.getMessage());
      } catch (HttpException ex) {
        System.err.println("Unrecoverable HTTP protocol violation: " + ex.getMessage());
      } finally {
        try {
          this.conn.shutdown();
        } catch (IOException ignored) {}
      }
    }

  }
}
