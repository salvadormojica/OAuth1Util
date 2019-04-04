@IsTest
private class OAuth1UtilTest {

    @IsTest
    static void testRequestTokenHMAC() {
        HttpResponse response;

        Test.setMock(HttpCalloutMock.class, new OAuth1UtilMock());
        Test.startTest();
        response = OAuth1Util.getRequestToken(
                OAuth1UtilMock.REQUEST_URL,
                OAuth1UtilMock.CONSUMER_KEY,
                OAuth1UtilMock.CONSUMER_SECRET,
                OAuth1UtilMock.HMAC,
                OAuth1UtilMock.REALM);
        Test.stopTest();

        System.assertEquals('oauth_token=' + OAuth1UtilMock.REQUEST_KEY + '&oauth_token_secret=' + OAuth1UtilMock.REQUEST_SECRET,
                response.getBody(), 'Response should contain request key and request secret');
    }

    @IsTest
    static void testRequestTokenPLAIN() {
        HttpResponse response;

        Test.setMock(HttpCalloutMock.class, new OAuth1UtilMock());
        Test.startTest();
        response = OAuth1Util.getRequestToken(
                OAuth1UtilMock.REQUEST_URL,
                OAuth1UtilMock.CONSUMER_KEY,
                OAuth1UtilMock.CONSUMER_SECRET,
                OAuth1UtilMock.PLAINTEXT,
                OAuth1UtilMock.REALM);
        Test.stopTest();

        System.assertEquals('oauth_token=' + OAuth1UtilMock.REQUEST_KEY + '&oauth_token_secret=' + OAuth1UtilMock.REQUEST_SECRET,
                response.getBody(), 'Response should contain request key and request secret');
    }

    @IsTest
    static void testAccessTokenHMAC() {
        HttpResponse response;

        Test.setMock(HttpCalloutMock.class, new OAuth1UtilMock());
        Test.startTest();
        response = OAuth1Util.getAccessToken(
                OAuth1UtilMock.ACCESS_URL,
                OAuth1UtilMock.CONSUMER_KEY,
                OAuth1UtilMock.CONSUMER_SECRET,
                OAuth1UtilMock.HMAC,
                OAuth1UtilMock.REQUEST_KEY,
                OAuth1UtilMock.REQUEST_SECRET,
                OAuth1UtilMock.REALM);
        Test.stopTest();

        System.assertEquals('oauth_token=' + OAuth1UtilMock.ACCESS_KEY + '&oauth_token_secret=' + OAuth1UtilMock.ACCESS_SECRET,
                response.getBody(), 'Response should contain access key and access secret');
    }

    @IsTest
    static void testAccessTokenPLAIN() {
        HttpResponse response;

        Test.setMock(HttpCalloutMock.class, new OAuth1UtilMock());
        Test.startTest();
        response = OAuth1Util.getAccessToken(
                OAuth1UtilMock.ACCESS_URL,
                OAuth1UtilMock.CONSUMER_KEY,
                OAuth1UtilMock.CONSUMER_SECRET,
                OAuth1UtilMock.PLAINTEXT,
                OAuth1UtilMock.REQUEST_KEY,
                OAuth1UtilMock.REQUEST_SECRET,
                OAuth1UtilMock.REALM);
        Test.stopTest();

        System.assertEquals('oauth_token=' + OAuth1UtilMock.ACCESS_KEY + '&oauth_token_secret=' + OAuth1UtilMock.ACCESS_SECRET,
                response.getBody(), 'Response should contain access key and access secret');
    }

    @IsTest
    static void testAuthenticatedRequestHMAC() {
        HttpResponse response;

        Test.setMock(HttpCalloutMock.class, new OAuth1UtilMock());
        Test.startTest();
        response = OAuth1Util.sendAuthenticatedRequest(
                OAuth1UtilMock.AUTH_URL,
                OAuth1UtilMock.CONSUMER_KEY,
                OAuth1UtilMock.CONSUMER_SECRET,
                OAuth1UtilMock.HMAC,
                OAuth1UtilMock.ACCESS_KEY,
                OAuth1UtilMock.ACCESS_SECRET,
                OAuth1UtilMock.REALM,
                new Map<String, String> {'paramKey' => 'paramValue'},
                new Map<String, String> {'headerKey' => 'headerValue'},
                'body');
        Test.stopTest();

        System.assertEquals('You are authenticated!', response.getBody(), 'Response should say that you are authenticated!');
    }

    @IsTest
    static void testAuthenticatedRequestPLAIN() {
        HttpResponse response;

        Test.setMock(HttpCalloutMock.class, new OAuth1UtilMock());
        Test.startTest();
        response = OAuth1Util.sendAuthenticatedRequest(
                OAuth1UtilMock.AUTH_URL,
                OAuth1UtilMock.CONSUMER_KEY,
                OAuth1UtilMock.CONSUMER_SECRET,
                OAuth1UtilMock.PLAINTEXT,
                OAuth1UtilMock.ACCESS_KEY,
                OAuth1UtilMock.ACCESS_SECRET,
                OAuth1UtilMock.REALM,
                new Map<String, String> {'paramKey' => 'paramValue'},
                new Map<String, String> {'headerKey' => 'headerValue'},
                'body');
        Test.stopTest();

        System.assertEquals('You are authenticated!', response.getBody(), 'Response should say that you are authenticated!');
    }
}