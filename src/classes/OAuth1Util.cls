/**
 * Util to sign HttpRequests for OAuth 1.0
 * This implementation was tested with http://oauthbin.com/ for HMAC-SHA1 and PLAINTEXT
 */
public with sharing class OAuth1Util {
    private static Http http = new Http();

    /**
     * This method calls the endpoint to return an request oauth_token and request oauth_token_secret
     *
     * @param requestEndpoint The endpoint where we are requesting an OAuth token
     * @param consumerKey A value used by the Consumer to identify itself to the Service Provider
     * @param consumerSecret A secret used by the Consumer to establish ownership of the Consumer Key
     * @param signatureMethod This implementation only supports "HMAC-SHA1" or "PLAINTEXT". Future implementations might support "RSA-SHA1"
     * @param realm OPTIONAL Protection realm for the request. If not used, set to null
     *
     * @return The HttpResponse object from the endpoint
     */
    public static HttpResponse getRequestToken(String requestEndpoint, String consumerKey, String consumerSecret, String signatureMethod, String realm) {
        HttpRequest request = constructRequest(requestEndpoint, consumerKey, consumerSecret, signatureMethod, null, '', realm, null, null, null);
        return http.send(request);
    }

    /**
     * This method calls the endpoint to return an access oauth_token and access oauth_token_secret
     *
     * @param requestEndpoint The endpoint where we are requesting an OAuth token
     * @param consumerKey A value used by the Consumer to identify itself to the Service Provider
     * @param consumerSecret A secret used by the Consumer to establish ownership of the Consumer Key
     * @param signatureMethod This implementation only supports "HMAC-SHA1" or "PLAINTEXT". Future implementations might support "RSA-SHA1"
     * @param requestToken The request token retrieved from the getRequestToken method
     * @param requestTokenSecret The request secret retrieved from the getRequestToken method
     * @param realm OPTIONAL Protection realm for the request. If not used, set to null
     *
     * @return The HttpResponse object from the endpoint
     */
    public static HttpResponse getAccessToken(String requestEndpoint, String consumerKey, String consumerSecret, String signatureMethod,
            String requestToken, String requestTokenSecret, String realm) {
        HttpRequest request = constructRequest(requestEndpoint, consumerKey, consumerSecret, signatureMethod, requestToken, requestTokenSecret, realm, null, null, null);
        return http.send(request);
    }

    /**
     * This method should be used to send any authenticated requests to the endpoint to retrieve any data
     *
     * @param requestEndpoint The endpoint where we are requesting an OAuth token
     * @param consumerKey A value used by the Consumer to identify itself to the Service Provider
     * @param consumerSecret A secret used by the Consumer to establish ownership of the Consumer Key
     * @param signatureMethod This implementation only supports "HMAC-SHA1" or "PLAINTEXT". Future implementations might support "RSA-SHA1"
     * @param accessToken The access token retrieved from the getAccessToken method
     * @param accessTokenSecret The access secret retrieved from the getAccessToken method
     * @param urlParameters Any url parameters that you want to add to the request
     * @param headers Any headers that you want to add to the request
     * @param body The request body
     * @param realm OPTIONAL Protection realm for the request. If not used, set to null
     *
     * @return The HttpResponse object from the endpoint
     */
    public static HttpResponse sendAuthenticatedRequest(String requestEndpoint, String consumerKey, String consumerSecret, String signatureMethod,
            String accessToken, String accessTokenSecret, String realm, Map<String, String> urlParameters, Map<String, String> headers, String body) {
        HttpRequest request = constructRequest(requestEndpoint, consumerKey, consumerSecret, signatureMethod, accessToken, accessTokenSecret, realm, urlParameters, headers, body);
        return http.send(request);
    }

    private static HttpRequest constructRequest(String requestEndpoint, String consumerKey, String consumerSecret, String signatureMethod,
            String requestToken, String requestTokenSecret, String realm, Map<String, String> urlParameters, Map<String, String> headers, String body) {
        HttpRequest request = new HttpRequest();
        request.setMethod('POST');

        // Set request body, headers and urlParams
        if (body == null) {
            request.setHeader('Content-Length', '0');
        } else {
            request.setBody(body);
        }
        if (headers != null && !headers.isEmpty()) {
            for (String key : headers.keySet()) {
                request.setHeader(key, headers.get(key));
            }
        }
        if (urlParameters != null && !urlParameters.isEmpty()) {
            requestEndpoint += '?';
            List<String> params = new List<String>();
            for (String key : urlParameters.keySet()) {
                params.add(key + '=' + urlParameters.get(key));
            }
            requestEndpoint += String.join(params, '&');
        }
        request.setEndpoint(requestEndpoint);

        Map<String, String> oauthParameters = new Map<String, String>();
        oauthParameters.put('oauth_consumer_key', consumerKey);
        if (requestToken != null) {
            oauthParameters.put('oauth_token', requestToken);
        }
        oauthParameters.put('oauth_signature_method', signatureMethod);
        oauthParameters.put('oauth_timestamp', getTimestamp());
        oauthParameters.put('oauth_nonce', getNonce());
        oauthParameters.put('oauth_version', '1.0');

        // Generate signature
        String baseString = createBaseString(oauthParameters, request);
        String signature;
        if (signatureMethod.equals('HMAC-SHA1')) {
            Blob signatureBlob = Crypto.generateMac('hmacSHA1', Blob.valueOf(baseString), Blob.valueOf(consumerSecret + '&' + requestTokenSecret));
            signature = EncodingUtil.urlEncode(EncodingUtil.base64Encode(signatureBlob), 'UTF-8');
        } else if (signatureMethod.equals('RSA-SHA1')) {
            throw new UnsupportedEncryptionException('OAuth1Util does not yet support RSA-SHA1 encryption!');
        } else if (signatureMethod.equals('PLAINTEXT')) {
            signature = consumerSecret + '&' + requestTokenSecret;
        } else {
            throw new UnsupportedEncryptionException('Encryption type is not supported or type doesn\'t match due to case sensitivity.');
        }

        // Generate authorization header
        String header = 'OAuth ';
        if(realm != null) {
            header += 'realm="' + realm + '",';
        }
        for (String key : oauthParameters.keySet()) {
            header += (key + '="' + oauthParameters.get(key) + '",');
        }
        header += ('oauth_signature="' + signature + '"');
        request.setHeader('Authorization', header);
        return request;
    }

    private static String createBaseString(Map<String,String> oauthParams, HttpRequest request) {
        Map<String,String> baseStringParams = oauthParams.clone();

        if (request.getMethod().equalsIgnoreCase('post') && request.getBody() != null &&
                request.getHeader('Content-Type') == 'application/x-www-form-urlencoded') {
            baseStringParams.putAll(getUrlParams(request.getBody()));
        }

        String host = request.getEndpoint();
        Integer n = host.indexOf('?');
        if (n > -1) {
            baseStringParams.putAll(getUrlParams(host.substring(n + 1)));
            host = host.substring(0, n);
        }

        List<String> keys = new List<String>();
        keys.addAll(baseStringParams.keySet());
        keys.sort();

        String paramString = keys.get(0) + '=' + baseStringParams.get(keys.get(0));
        for (Integer i = 1; i < keys.size(); i++) {
            paramString = paramString + '&' + keys.get(i) + '=' + baseStringParams.get(keys.get(i));
        }

        return request.getMethod().toUpperCase() + '&' + EncodingUtil.urlEncode(host, 'UTF-8') + '&' + EncodingUtil.urlEncode(paramString, 'UTF-8');
    }

    private static Map<String,String> getUrlParams(String paramString) {
        Map<String,String> nameValueMap = new Map<String,String>();

        if (paramString == null || paramString == '') {
            return nameValueMap;
        }

        for (String nameValuePair : paramString.split('&')) {
            List<String> nameValueList = nameValuePair.split('=');
            if (nameValueList.size() > 1) {
                // RFC 5849 section 3.4.1.3.1 and 3.4.1.3.2 specify that parameter names
                // and values are decoded then encoded before being sorted and concatenated
                // Section 3.6 specifies that space must be encoded as %20 and not +
                String encName = EncodingUtil.urlEncode(EncodingUtil.urlDecode(nameValueList[0], 'UTF-8'), 'UTF-8').replace('+','%20');
                String encValue = EncodingUtil.urlEncode(EncodingUtil.urlDecode(nameValueList[1], 'UTF-8'), 'UTF-8').replace('+','%20');
                nameValueMap.put(encName,encValue);
            }
        }

        return nameValueMap;
    }

    private static String getTimestamp() {
        return String.valueOf(Datetime.now().getTime() / 1000);
    }

    private static String getNonce() {
        Blob hashSeed = Blob.valueOf(Datetime.now() + '' + Crypto.getRandomLong());
        return EncodingUtil.convertToHex(Crypto.generateDigest('MD5', hashSeed));
    }

    private class UnsupportedEncryptionException extends Exception {}
}