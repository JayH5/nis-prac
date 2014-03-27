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

  /** Default handler for all unknown requests. Just returns 404 */
  static class DefaultHandler implements HttpRequestHandler {
    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context) {
      String method = request.getRequestLine().getMethod().toUpperCase(Locale.ENGLISH);
      String target = request.getRequestLine().getUri();

      System.out.println("Unknown request: " + method + " " + target);

      // Respond with a 404
      HttpUtils.notFound(response);
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
