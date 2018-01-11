/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.bitbucket.authentication;

import io.curity.identityserver.plugin.bitbucket.config.BitbucketAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.Attributes;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpRequest;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.WebServiceClient;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.EMAILS;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.REPOSITORIES;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.TEAMS;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.USER;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.USERNAME;

public class CallbackRequestHandler implements AuthenticatorRequestHandler<CallbackGetRequestModel>
{
    private final static Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final ExceptionFactory _exceptionFactory;
    private final BitbucketAuthenticatorPluginConfig _config;
    private final Json _json;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final WebServiceClientFactory _webServiceClientFactory;

    public CallbackRequestHandler(BitbucketAuthenticatorPluginConfig config)
    {
        _exceptionFactory = config.getExceptionFactory();
        _config = config;
        _json = config.getJson();
        _webServiceClientFactory = config.getWebServiceClientFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
    }

    @Override
    public CallbackGetRequestModel preProcess(Request request, Response response)
    {
        if (request.isGetRequest())
        {
            return new CallbackGetRequestModel(request);
        }
        else
        {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> post(CallbackGetRequestModel requestModel, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackGetRequestModel requestModel, Response response)
    {
        validateState(requestModel.getState());
        handleError(requestModel);

        Map<String, Object> tokenResponseData = redeemCodeForTokens(requestModel);


        AuthenticationResult authenticationResult = getAuthenticationResult(tokenResponseData);

        return Optional.of(authenticationResult);
    }

    private Map<String, Object> redeemCodeForTokens(CallbackGetRequestModel requestModel)
    {
        HttpResponse tokenResponse = getWebServiceClient()
                .withPath("/site/oauth2/access_token")
                .request()
                .contentType("application/x-www-form-urlencoded")
                .body(getFormEncodedBodyFrom(createPostData(_config.getClientId(), _config.getClientSecret(),
                        requestModel.getCode(), requestModel.getRequestUrl())))
                .method("POST")
                .response();
        int statusCode = tokenResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isInfoEnabled())
            {
                _logger.info("Got error response from token endpoint: error = {}, {}", statusCode,
                        tokenResponse.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        return _json.fromJson(tokenResponse.body(HttpResponse.asString()));
    }

    private AuthenticationResult getAuthenticationResult(Map<String, Object> tokenResponseData)
    {
        String accessToken = tokenResponseData.get("access_token").toString();
        String refreshToken = null;
        if (tokenResponseData.get("refresh_token") != null)
        {
            refreshToken = tokenResponseData.get("refresh_token").toString();
        }

        Map<String, Object> profileData = executeRequest("/1.0/user", accessToken, false);
        Map<String, Object> userAuthenticationData = new HashMap<>();
        String username = ((Map) profileData.get(USER)).get(USERNAME).toString();
        userAuthenticationData.put(USERNAME, username);

        getRepositories(profileData, userAuthenticationData, accessToken);
        getAccountInfo(profileData, userAuthenticationData, accessToken, username);
        getEmails(userAuthenticationData, accessToken, username);
        getTeams(userAuthenticationData, accessToken, _config.isGetTeams());
        checkTeamMembership(userAuthenticationData, accessToken);


        AuthenticationAttributes attributes = AuthenticationAttributes.of(
                SubjectAttributes.of(username, Attributes.fromMap(userAuthenticationData)),
                ContextAttributes.of(Attributes.of(
                        Attribute.of("access_token", accessToken),
                        Attribute.of("refresh_token", refreshToken)
                )));
        AuthenticationResult authenticationResult = new AuthenticationResult(attributes);

        return authenticationResult;
    }

    private void checkTeamMembership(Map<String, Object> userAuthenticationData, String accessToken)
    {
        _config.getTeamName().ifPresent(teamName -> {
            getTeams(userAuthenticationData, accessToken, true);
            List teamsData = (ArrayList<Object>) ((Map<String, Object>) userAuthenticationData.get(TEAMS)).get("values");
            boolean isTeamMember = false;
            for (Object item : teamsData)
            {
                Map<String, Object> value = (Map<String, Object>) item;
                if (teamName.equalsIgnoreCase(value.get(USERNAME).toString()))
                {
                    isTeamMember = true;
                }
            }

            if (!isTeamMember)
            {
                _logger.warn("User is not a member of specified team.");
                throw _exceptionFactory.internalServerException(ErrorCode.ACCESS_DENIED, "Access denied to specified team.");
            }
        });
    }

    private void getTeams(Map<String, Object> userAuthenticationData, String accessToken, boolean isGetTeams)
    {
        if (isGetTeams && userAuthenticationData.get(TEAMS) == null)
        {
            Map<String, Object> teamsData = executeRequest("/2.0/teams?role=member", accessToken, false);
            userAuthenticationData.put(TEAMS, teamsData);
        }
    }

    private void getAccountInfo(Map<String, Object> userProfileData, Map<String, Object> userAuthenticationData, String accessToken, String username)
    {
        if (_config.isGetAccountInformation())
        {
            if (userProfileData.get(USER) != null)
            {
                userAuthenticationData.put(USER, userProfileData.get(USER));
            }
            else
            {
                Map<String, Object> accountData = executeRequest("/1.0/users/" + username, accessToken, false);
                userAuthenticationData.put(USER, accountData);
            }
        }
    }

    private void getEmails(Map<String, Object> userAuthenticationData, String accessToken, String username)
    {
        if (_config.isGetEmails())
        {
            Map<String, Object> emailsData = executeRequest("/1.0/users/" + username + "/emails", accessToken, true);
            userAuthenticationData.put(EMAILS, emailsData.get("data"));
        }
    }

    private void getRepositories(Map<String, Object> userProfileData, Map<String, Object> userAuthenticationData, String accessToken)
    {
        if (_config.isGetRepositories())
        {
            if (userProfileData.get(REPOSITORIES) != null)
            {
                userAuthenticationData.put(REPOSITORIES, userProfileData.get(REPOSITORIES));
            }
            else
            {
                Map<String, Object> respositoriesData = executeRequest("/1.0/user/repositories", accessToken, false);
                userAuthenticationData.put(REPOSITORIES, respositoriesData.get("data"));
            }
        }
    }

    private Map<String, Object> executeRequest(String requestPath, String accessToken, boolean isArrayResponse)
    {
        HttpResponse tokenResponse = getWebServiceAPIClient()
                .withPath(requestPath)
                .request()
                .contentType("application/json")
                .header("Authorization", "Bearer " + accessToken)
                .method("GET")
                .response();
        int statusCode = tokenResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isInfoEnabled())
            {
                _logger.info("Got error response from token endpoint: error = {}, {}", statusCode,
                        tokenResponse.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        if (isArrayResponse)
        {
            List list = _json.fromJsonArray(tokenResponse.body(HttpResponse.asString()));
            Map<String, Object> map = new HashMap<>();
            map.put("data", list);
            return map;
        }

        return _json.fromJson(tokenResponse.body(HttpResponse.asString()));
    }


    private WebServiceClient getWebServiceClient()
    {
        Optional<HttpClient> httpClient = _config.getHttpClient();

        if (httpClient.isPresent())
        {
            return _webServiceClientFactory.create(httpClient.get()).withHost("bitbucket.org");
        }
        else
        {
            return _webServiceClientFactory.create(URI.create("https://bitbucket.org"));
        }
    }

    private WebServiceClient getWebServiceAPIClient()
    {
        Optional<HttpClient> httpClient = _config.getHttpClient();

        if (httpClient.isPresent())
        {
            return _webServiceClientFactory.create(httpClient.get()).withHost("api.bitbucket.org");
        }
        else
        {
            return _webServiceClientFactory.create(URI.create("https://api.bitbucket.org"));
        }
    }

    private void handleError(CallbackGetRequestModel requestModel)
    {
        if (!Objects.isNull(requestModel.getError()))
        {
            if ("access_denied".equals(requestModel.getError()))
            {
                _logger.debug("Got an error from Bitbucket: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

                throw _exceptionFactory.redirectException(
                        _authenticatorInformationProvider.getAuthenticationBaseUri().toASCIIString());
            }

            _logger.warn("Got an error from Bitbucket: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

            throw _exceptionFactory.externalServiceException("Login with Bitbucket failed");
        }
    }

    private static Map<String, String> createPostData(String clientId, String clientSecret, String code, String callbackUri)
    {
        Map<String, String> data = new HashMap<>(5);

        data.put("client_id", clientId);
        data.put("client_secret", clientSecret);
        data.put("code", code);
        data.put("grant_type", "authorization_code");
        data.put("redirect_uri", callbackUri);

        return data;
    }

    private static HttpRequest.BodyProcessor getFormEncodedBodyFrom(Map<String, String> data)
    {
        StringBuilder stringBuilder = new StringBuilder();

        data.entrySet().forEach(e -> appendParameter(stringBuilder, e));

        return HttpRequest.fromString(stringBuilder.toString());
    }

    private static void appendParameter(StringBuilder stringBuilder, Map.Entry<String, String> entry)
    {
        String key = entry.getKey();
        String value = entry.getValue();
        String encodedKey = urlEncodeString(key);
        stringBuilder.append(encodedKey);

        if (!Objects.isNull(value))
        {
            String encodedValue = urlEncodeString(value);
            stringBuilder.append("=").append(encodedValue);
        }

        stringBuilder.append("&");
    }

    private static String urlEncodeString(String unencodedString)
    {
        try
        {
            return URLEncoder.encode(unencodedString, StandardCharsets.UTF_8.name());
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException("This server cannot support UTF-8!", e);
        }
    }

    private void validateState(String state)
    {
        @Nullable Attribute sessionAttribute = _config.getSessionManager().get("state");

        if (sessionAttribute != null && state.equals(sessionAttribute.getValueOfType(String.class)))
        {
            _logger.debug("State matches session");
        }
        else
        {
            _logger.debug("State did not match session");

            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE, "Bad state provided");
        }
    }
}
