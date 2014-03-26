import java.nio.charset.Charset;
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

public final class HttpUtils {

  public static String parseMethod(HttpRequest request) {
    return request.getRequestLine().getMethod().toUpperCase(Locale.ENGLISH);
  }

  public static Map<String, String> parseQueryParams(String data) {
    List<NameValuePair> formData = URLEncodedUtils.parse(data, Charset.forName("UTF-8"));

    Map<String, String> queryParams = new HashMap<String, String>(formData.size());
    for (NameValuePair param : formData) {
      queryParams.put(param.getName(), param.getValue());
    }
    return queryParams;
  }

  public static String parseStringContent(HttpRequest request) {
    String content = null;
    if (request instanceof HttpEntityEnclosingRequest) {
      HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
      content = EntityUtils.toString(entity);
    }
    return content
  }

  public static void notFound(HttpResponse response) {
    response.setStatusCode(HttpStatus.SC_NOT_FOUND);
    StringEntity entity = new StringEntity(
        "<html><body><h1>404 NOT FOUND</h1></body></html>",
        ContentType.create("text/html", "UTF-8"));
    response.setEntity(entity);
  }

  public static void forbidden(HttpResponse response) {
    response.setStatusCode(HttpStatus.SC_FORBIDDEN);
    StringEntity entity = new StringEntity(
        "<html><body><h1>403 FORBIDDEN</h1></body></html>",
        ContentType.create("text/html", "UTF-8"));
    response.setEntity(entity);
  }

}