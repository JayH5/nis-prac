import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

public final class HttpUtils {

  private static final Comparator<NameValuePair> PARAM_COMPARATOR =
      new Comparator<NameValuePair>() {
    @Override
    public int compare(NameValuePair o1, NameValuePair o2) {
      return o1.getName().compareTo(o2.getName());
    }
  };

  /** Parse the method of the given request. e.g. POST, GET */
  public static String parseMethod(HttpRequest request) {
    return request.getRequestLine().getMethod().toUpperCase(Locale.ENGLISH);
  }

  /** Parse the query parameters from either a URI or a post body. */
  public static Map<String, String> parseQueryParams(String data) {
    List<NameValuePair> formData = URLEncodedUtils.parse(data, Charset.forName("UTF-8"));

    Map<String, String> queryParams = new HashMap<String, String>(formData.size());
    for (NameValuePair param : formData) {
      queryParams.put(param.getName(), param.getValue());
    }
    return queryParams;
  }

  /**
   * Consumes the given request and parses the contained data into a String.
   */
  public static String parseStringContent(HttpRequest request) throws IOException {
    String content = null;
    if (request instanceof HttpEntityEnclosingRequest) {
      HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
      content = EntityUtils.toString(entity);
    }
    return content;
  }

  public static void addSignatureToRequest(String method, String path, List<NameValuePair> params) {
    String signature = Utils.sha1Hash(stringToSign(method, path, buildParamsString(params)));
    params.add(new BasicNameValuePair("signature", signature));
  }

  /** Build a list of *unencoded* parameters into a single string. */
  public static String buildParamsString(List<NameValuePair> params) {
    // Sort first to ensure consistency
    Collections.sort(params, PARAM_COMPARATOR);
    return URLEncodedUtils.format(params, "UTF-8");
  }

  public static String buildParamsString(Map<String, String> params) {
    List<NameValuePair> paramsList = new ArrayList<NameValuePair>();
    for(Map.Entry<String, String> param : params.entrySet()) {
      paramsList.add(new BasicNameValuePair(param.getKey(), param.getValue()));
    }
    Collections.sort(paramsList, PARAM_COMPARATOR);
    return URLEncodedUtils.format(paramsList, "UTF-8");
  }

  /** Build a string to sign. */
  public static String stringToSign(String method, String path, String params) {
    StringBuilder sb = new StringBuilder();
    sb.append(method).append('\n').append(path).append('\n').append(params);
    return sb.toString();
  }

  /**
   * Consumes the given request and parses the contained data into a byte array.
   */
  public static byte[] parseByteArrayContent(HttpRequest request) throws IOException {
    byte[] content = null;
    if (request instanceof HttpEntityEnclosingRequest) {
      HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
      content = EntityUtils.toByteArray(entity);
    }
    return content;
  }

  /** Set the given response to contain the default 404/not found message. */
  public static void notFound(HttpResponse response) {
    response.setStatusCode(HttpStatus.SC_NOT_FOUND);
    StringEntity entity = new StringEntity(
        "<html><body><h1>404 NOT FOUND</h1></body></html>",
        ContentType.create("text/html", "UTF-8"));
    response.setEntity(entity);
  }

  /** Set the given response to contain the default 403/forbidden message. */
  public static void forbidden(HttpResponse response) {
    response.setStatusCode(HttpStatus.SC_FORBIDDEN);
    StringEntity entity = new StringEntity(
        "<html><body><h1>403 FORBIDDEN</h1></body></html>",
        ContentType.create("text/html", "UTF-8"));
    response.setEntity(entity);
  }

}