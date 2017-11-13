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

import com.google.common.collect.ImmutableMap;
import io.curity.identityserver.plugin.authentication.CodeFlowOAuthClient;
import io.curity.identityserver.plugin.authentication.OAuthClient;
import io.curity.identityserver.plugin.bitbucket.config.BitbucketAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.authentication.Constants.Params.PARAM_REDIRECT_URI;
import static io.curity.identityserver.plugin.authentication.OAuthClient.notNullOrEmpty;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.SCOPE_ACCOUNT;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.SCOPE_EMAIL;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.SCOPE_REPOSITORY;
import static io.curity.identityserver.plugin.bitbucket.authentication.Constants.SCOPE_TEAM;

public class BitbucketAuthenticatorRequestHandler implements AuthenticatorRequestHandler<RequestModel> {
    private static final Logger _logger = LoggerFactory.getLogger(BitbucketAuthenticatorRequestHandler.class);

    private final BitbucketAuthenticatorPluginConfig _config;
    private final OAuthClient _oauthClient;

    public BitbucketAuthenticatorRequestHandler(BitbucketAuthenticatorPluginConfig config,
                                                ExceptionFactory exceptionFactory,
                                                Json json,
                                                AuthenticatorInformationProvider provider) {
        _config = config;
        _oauthClient = new CodeFlowOAuthClient(exceptionFactory, provider, json, config.getSessionManager());
    }

    @Override
    public Optional<AuthenticationResult> get(RequestModel requestModel, Response response) {
        _logger.info("GET request received for authentication");

        _oauthClient.setServiceProviderId(requestModel.getRequest());
        return requestAuthentication(response, ImmutableMap.of(PARAM_REDIRECT_URI, _oauthClient.getCallbackUrl()));
    }

    @Override
    public Optional<AuthenticationResult> post(RequestModel requestModel, Response response) {
        return Optional.empty();
    }

    @Override
    public RequestModel preProcess(Request request, Response response) {
        return new RequestModel(request);
    }

    public Optional<AuthenticationResult> requestAuthentication(Response response, Map<String, String> extraAuthorizeParameters) {
        ImmutableMap.Builder<String, String> builder = ImmutableMap.<String, String>builder()
                .putAll(extraAuthorizeParameters);

        String scope = "";
        if (notNullOrEmpty(_config.getTeamName()) || _config.isGetTeams()) {
            scope = SCOPE_TEAM;
        } else if (_config.isGetEmails()) {
            scope += " " + SCOPE_EMAIL;
        } else if (_config.isGetAccountInformation()) {
            scope += " " + SCOPE_ACCOUNT;
        } else if (_config.isGetRepositories()) {
            scope += " " + SCOPE_REPOSITORY;
        }

        _oauthClient.redirectToAuthorizationEndpoint(response,
                _config.getAuthorizationEndpoint().toString(),
                _config.getClientId(),
                scope,
                builder.build());

        return Optional.empty();
    }
}