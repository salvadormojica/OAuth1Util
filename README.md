# OAuth1Util
The purpose of writing this utility was the need to integrate Salesforce with a system that was not yet updated to use OAuth2. Salesforce had since removed the ability to easily configure your organization to use OAuth 1, so we had to write our own.
There are a few other OAuth1 projects floating about, but I found them to be a bit overengineered.
While I understand that this may not be the most secure way to connect to another system, if there is no way other than to use OAuth1, then here it is.

## API
### getRequestToken
This method calls the endpoint to return an request oauth_token and request oauth_token_secret
```@param requestEndpoint The endpoint where we are requesting an OAuth token
@param consumerKey A value used by the Consumer to identify itself to the Service Provider
@param consumerSecret A secret used by the Consumer to establish ownership of the Consumer Key
@param signatureMethod This implementation only supports "HMAC-SHA1" or "PLAINTEXT". Future implementations might support "RSA-SHA1"
@param realm OPTIONAL Protection realm for the request. If not used, set to null

getRequestToken(String requestEndpoint, String consumerKey, String consumerSecret, String signatureMethod, String realm)
```
### getAccessToken
This method calls the endpoint to return an access oauth_token and access oauth_token_secret
```@param requestEndpoint The endpoint where we are requesting an OAuth token
@param consumerKey A value used by the Consumer to identify itself to the Service Provider
@param consumerSecret A secret used by the Consumer to establish ownership of the Consumer Key
@param signatureMethod This implementation only supports "HMAC-SHA1" or "PLAINTEXT". Future implementations might support "RSA-SHA1"
@param requestToken The request token retrieved from the getRequestToken method
@param requestTokenSecret The request secret retrieved from the getRequestToken method
@param realm OPTIONAL Protection realm for the request. If not used, set to null

getAccessToken(String requestEndpoint, String consumerKey, String consumerSecret, String signatureMethod, String requestToken, String requestTokenSecret, String realm)
```
### sendAuthenticatedRequest
This method should be used to send any authenticated requests to the endpoint to retrieve any data
```@param requestEndpoint The endpoint where we are requesting an OAuth token
@param consumerKey A value used by the Consumer to identify itself to the Service Provider
@param consumerSecret A secret used by the Consumer to establish ownership of the Consumer Key
@param signatureMethod This implementation only supports "HMAC-SHA1" or "PLAINTEXT". Future implementations might support "RSA-SHA1"
@param accessToken The access token retrieved from the getAccessToken method
@param accessTokenSecret The access secret retrieved from the getAccessToken method
@param urlParameters Any url parameters that you want to add to the request
@param headers Any headers that you want to add to the request
@param body The request body
@param realm OPTIONAL Protection realm for the request. If not used, set to null

sendAuthenticatedRequest(String requestEndpoint, String consumerKey, String consumerSecret, String signatureMethod, String accessToken, String accessTokenSecret, String realm, Map<String, String> urlParameters, Map<String, String> headers, String body)
```
