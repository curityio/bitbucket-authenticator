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

import io.curity.identityserver.plugin.authentication.CodeFlowOAuthClient;
import io.curity.identityserver.plugin.authentication.OAuthClient;
import io.curity.identityserver.plugin.bitbucket.config.BitbucketAuthenticatorPluginConfig;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.Attributes;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.authentication.Constants.BEARER;
import static io.curity.identityserver.plugin.authentication.Constants.Params.PARAM_ACCESS_TOKEN;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.*;
import static org.apache.http.HttpHeaders.AUTHORIZATION;

public class CallbackRequestHandler
        implements AuthenticatorRequestHandler<CallbackGetRequestModel> {
    private static final Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final ExceptionFactory _exceptionFactory;
    private final OAuthClient _oauthClient;
    private final BitbucketAuthenticatorPluginConfig _config;
    private final HttpClient _client;
    private final Json _json;

    public CallbackRequestHandler(ExceptionFactory exceptionFactory,
                                  AuthenticatorInformationProvider provider,
                                  Json json,
                                  BitbucketAuthenticatorPluginConfig config) {
        _exceptionFactory = exceptionFactory;
        _oauthClient = new CodeFlowOAuthClient(exceptionFactory, provider, json, config.getSessionManager());
        _config = config;
        _client = HttpClientBuilder.create().build();
        _json = json;
    }

    @Override
    public CallbackGetRequestModel preProcess(Request request, Response response) {
        if (request.isGetRequest()) {
            return new CallbackGetRequestModel(request);
        } else {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackGetRequestModel requestModel,
                                              Response response) {
        _oauthClient.redirectToAuthenticationOnError(requestModel.getRequest(), _config.id());

        Map<String, Object> tokenMap = _oauthClient.getTokens(_config.getTokenEndpoint().toString(),
                _config.getClientId(),
                _config.getClientSecret(),
                requestModel.getCode(),
                requestModel.getState());
        Optional<AuthenticationResult> authenticationResult = getAuthenticationResult(tokenMap);
        return authenticationResult;
    }

    private Optional<AuthenticationResult> getAuthenticationResult(Map<String, Object> tokenMap) {
        String accessToken = tokenMap.get(PARAM_ACCESS_TOKEN).toString();
        String refreshToken = null;
        if (tokenMap.get(REFRESH_TOKEN) != null) {
            refreshToken = tokenMap.get(REFRESH_TOKEN).toString();
        }
        HttpGet getRequest = new HttpGet(USER_PROFILE_URL);
        setAuthorizationHeader(getRequest, accessToken);
        Map<String, Object> profileData = executeRequest(getRequest, false);
        Map<String, Object> userAuthenticationData = new HashMap<>();
        String username = ((Map) profileData.get(USER)).get(USERNAME).toString();
        userAuthenticationData.put(USERNAME, username);

        getRepositories(profileData, userAuthenticationData, accessToken);
        getAccountInfo(profileData, userAuthenticationData, accessToken, username);
        getEmails(userAuthenticationData, accessToken, username);
        getTeams(userAuthenticationData, accessToken);


        AuthenticationAttributes attributes = AuthenticationAttributes.of(
                SubjectAttributes.of(username, Attributes.fromMap(userAuthenticationData)),
                ContextAttributes.of(Attributes.of(
                        Attribute.of(PARAM_ACCESS_TOKEN, accessToken),
                        Attribute.of(REFRESH_TOKEN, refreshToken)
                )));
        AuthenticationResult authenticationResult = new AuthenticationResult(attributes);

        return Optional.of(authenticationResult);
    }

    private void getTeams(Map<String, Object> userAuthenticationData, String accessToken) {
        if (_config.isGetTeams()) {
            HttpGet getRequest = new HttpGet(TEAMS_URL);
            setAuthorizationHeader(getRequest, accessToken);
            Map<String, Object> teamsData = executeRequest(getRequest, false);
            userAuthenticationData.put(TEAMS, teamsData);
        }
    }

    private void getAccountInfo(Map<String, Object> userProfileData, Map<String, Object> userAuthenticationData, String accessToken, String username) {
        if (_config.isGetAccountInformation()) {
            if (userProfileData.get(USER) != null) {
                userAuthenticationData.put(USER, userProfileData.get(USER));
            } else {
                HttpGet getRequest = new HttpGet(ACCOUNT_URL + username);
                setAuthorizationHeader(getRequest, accessToken);
                Map<String, Object> accountData = executeRequest(getRequest, false);
                userAuthenticationData.put(USER, accountData);
            }
        }
    }

    private void getEmails(Map<String, Object> userAuthenticationData, String accessToken, String username) {
        if (_config.isGetEmails()) {
            HttpGet getRequest = new HttpGet(EMAILS_URL.replace("{accountname}", username));
            setAuthorizationHeader(getRequest, accessToken);
            Map<String, Object> emailsData = executeRequest(getRequest, true);
            userAuthenticationData.put(EMAILS, emailsData.get("data"));
        }
    }

    private void getRepositories(Map<String, Object> userProfileData, Map<String, Object> userAuthenticationData, String accessToken) {
        if (_config.isGetRepositories()) {
            if (userProfileData.get(REPOSITORIES) != null) {
                userAuthenticationData.put(REPOSITORIES, userProfileData.get(REPOSITORIES));
            } else {
                HttpGet getRequest = new HttpGet(REPOSITORIES_URL);
                setAuthorizationHeader(getRequest, accessToken);
                Map<String, Object> respositoriesData = executeRequest(getRequest, true);
                userAuthenticationData.put(REPOSITORIES, respositoriesData.get("data"));
            }
        }
    }

    private Map<String, Object> executeRequest(HttpGet request, boolean isArrayResponse) {
        try {
            HttpResponse response = _client.execute(request);
            if (response.getStatusLine().getStatusCode() != org.apache.http.HttpStatus.SC_OK) {
                _logger.debug("Got error response from endpoint {}, with status line {}", request.getURI().toString(), response.getStatusLine());

                throw _exceptionFactory.internalServerException(ErrorCode.INVALID_SERVER_STATE, "INTERNAL SERVER ERROR");
            }
            if (isArrayResponse) {
                List list = parseResponseArray(response);
                Map<String, Object> map = new HashMap<>();
                map.put("data", list);
                return map;
            } else {
                return _oauthClient.parseResponse(response);
            }

        } catch (IOException e) {
            _logger.warn("Could not communicate with endpoint:" + request.getURI().toString(), e);
            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR, "Authentication failed");
        }
    }

    private void setAuthorizationHeader(HttpGet request, String accessToken) {
        request.setHeader(AUTHORIZATION, BEARER + accessToken);
    }

    private List parseResponseArray(HttpResponse response) {
        try {
            String jsonString = EntityUtils.toString(response.getEntity());

            return _json.fromJsonArray(jsonString);
        } catch (IOException e) {
            _logger.debug("Could not parse UserInfo", e);

            throw _exceptionFactory.internalServerException(ErrorCode.INVALID_SERVER_STATE, "Authentication failed");
        }
    }


    @Override
    public Optional<AuthenticationResult> post(CallbackGetRequestModel requestModel,
                                               Response response) {
        throw _exceptionFactory.methodNotAllowed();
    }

}
