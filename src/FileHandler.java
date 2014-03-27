import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;

public class FileHandler implements HttpRequestHandler {
  private final AuthManager authManager;
  private final String docRoot;

  public FileHandler(AuthManager authManager, String docRoot) {
    this.authManager = authManager;
    this.docRoot = docRoot;
  }

  @Override
  public void handle(HttpRequest request, HttpResponse response, HttpContext context)
      throws HttpException, IOException {
    String method = HttpUtils.parseMethod(request);
    if (!method.equals("GET") && !method.equals("POST")) {
      throw new MethodNotSupportedException(method + " method not supported");
    }
    String target = request.getRequestLine().getUri();

    // Parse the params
    Map<String, String> params = HttpUtils.parseQueryParams(target);

    // Find signature among parameters
    String signature = params.get("signature");

    System.out.println("Signature= " + signature);

    byte[] entityContent = null;
    if (method.equals("POST")) {
      entityContent = HttpUtils.parseByteArrayContent(request);
      System.out.println("Incoming entity content (bytes): " + entityContent.length);
    }

    if (authManager.isValidSignature(signature, entityContent)) {
      System.out.println("Signature verified!");
    } else {
      System.out.println("Signature check failed!");
      HttpUtils.forbidden(response);
      return;
    }

    // Check if the file exists, upload if it does
    // TODO: File stuff... it's broken
    File file = new File(this.docRoot, target);
    if (!file.exists()) {
      HttpUtils.notFound(response);
      System.out.println("File " + file.getPath() + " not found");
    } else if (!file.canRead() || file.isDirectory()) {
      HttpUtils.forbidden(response);
      System.out.println("Cannot read file " + file.getPath());
    } else {
      response.setStatusCode(HttpStatus.SC_OK);
      FileEntity body = new FileEntity(file, ContentType.create("text/html", (Charset) null));
      response.setEntity(body);
      System.out.println("Serving file " + file.getPath());
    }
  }
}