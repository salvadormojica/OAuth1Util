@IsTest
public class OAuth1UtilMock implements HttpCalloutMock {

    public static final String REQUEST_URL = '/request-token';
    public static final String ACCESS_URL = '/access-token';
    public static final String AUTH_URL = '/auth-url';

    public static final String CONSUMER_KEY = 'key';
    public static final String CONSUMER_SECRET = 'secret';
    public static final String REQUEST_KEY = 'requestkey';
    public static final String REQUEST_SECRET = 'requestsecret';
    public static final String ACCESS_KEY = 'accesskey';
    public static final String ACCESS_SECRET = 'accesssecret';

    public static final String REALM = 'testRealm';
    public static final String HMAC = 'HMAC-SHA1';
    public static final String PLAINTEXT = 'PLAINTEXT';

    public HttpResponse respond(HttpRequest request) {
        HttpResponse response = new HttpResponse();
        response.setStatusCode(200);
        response.setStatus('success');
        if (request.getEndpoint().startsWith(REQUEST_URL)) {
            response.setBody('oauth_token=' + REQUEST_KEY + '&oauth_token_secret=' + REQUEST_SECRET);
        } else if (request.getEndpoint().startsWith(ACCESS_URL)) {
            response.setBody('oauth_token=' + ACCESS_KEY + '&oauth_token_secret=' + ACCESS_SECRET);
        } else if (request.getEndpoint().startsWith(AUTH_URL)) {
            response.setBody('You are authenticated!');
        } else {
            response.setBody('You are not authorized!');
        }
        return response;
    }
}