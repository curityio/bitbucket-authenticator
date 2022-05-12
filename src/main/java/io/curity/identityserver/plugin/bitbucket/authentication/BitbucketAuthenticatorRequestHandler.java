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
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.http.RedirectStatusCode;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static io.curity.identityserver.plugin.bitbucket.authentication.RedirectUriUtil.createRedirectUri;

public class BitbucketAuthenticatorRequestHandler implements AuthenticatorRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(BitbucketAuthenticatorRequestHandler.class);
    private static final String AUTHORIZATION_ENDPOINT = "https://bitbucket.org/site/oauth2/authorize";

    private final BitbucketAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final ExceptionFactory _exceptionFactory;

    public BitbucketAuthenticatorRequestHandler(BitbucketAuthenticatorPluginConfig config)
    {
        _config = config;
        _exceptionFactory = config.getExceptionFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
    }

    @Override
    public Optional<AuthenticationResult> get(Request request, Response response)
    {
        _logger.debug("GET request received for authentication authentication");

        String redirectUri = createRedirectUri(_authenticatorInformationProvider, _exceptionFactory);
        String state = UUID.randomUUID().toString();
        Map<String, Collection<String>> queryStringArguments = new LinkedHashMap<>(5);
        Set<String> scopes = new LinkedHashSet<>(7);

        _config.getSessionManager().put(Attribute.of("state", state));

        queryStringArguments.put("client_id", Collections.singleton(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Collections.singleton(redirectUri));
        queryStringArguments.put("state", Collections.singleton(state));
        queryStringArguments.put("response_type", Collections.singleton("code"));

        handleScopes(scopes);

        queryStringArguments.put("scope", Collections.singleton(String.join(" ", scopes)));

        _logger.debug("Redirecting to {} with query string arguments {}", AUTHORIZATION_ENDPOINT,
                queryStringArguments);

        throw _exceptionFactory.redirectException(AUTHORIZATION_ENDPOINT,
                RedirectStatusCode.MOVED_TEMPORARILY, queryStringArguments, false);
    }

    private void handleScopes(Set<String> scopes)
    {
        _config.getTeamName().ifPresent(teamName -> {
            if (_config.isGetTeams())
            {
                scopes.add("team");
            }
        });

        if (_config.isGetEmails())
        {
            scopes.add("email");
        }
        if (_config.isGetAccountInformation())
        {
            scopes.add("account");
        }
        if (_config.isGetRepositories())
        {
            scopes.add("repository");
        }
        switch (_config.getRepositoryAccess())
        {
            case READ:
                if (!_config.isGetRepositories())
                {
                    scopes.add("repository");
                }
                break;
            case WRITE:
                scopes.add("repository:write");
        }
        if (_config.isRepositoryAdmin())
        {
            scopes.add("repository:admin");
        }
        switch (_config.getSnippetAccess())
        {
            case READ:
                scopes.add("snippet");
                break;
            case WRITE:
                scopes.add("snippet:write");
        }
        switch (_config.getIssueAccess())
        {
            case READ:
                scopes.add("issue");
                break;
            case WRITE:
                scopes.add("issue:write");
        }
        if (_config.isWikiAccess())
        {
            scopes.add("wiki");
        }
        switch (_config.getPullRequestAccess())
        {
            case READ:
                scopes.add("pullrequest");
                break;
            case WRITE:
                scopes.add("pullrequest:write");
        }
        switch (_config.getAccountAccess())
        {
            case READ:
                if (!_config.isGetAccountInformation())
                {
                    scopes.add("account");
                }
                break;
            case WRITE:
                scopes.add("account:write");
        }
        switch (_config.getTeamAccess())
        {
            case READ:
                if (!_config.isGetTeams())
                {
                    scopes.add("team");
                }
                break;
            case WRITE:
                scopes.add("team:write");
        }
        if (_config.isWebhookAccess())
        {
            scopes.add("webhook");
        }


    }

    @Override
    public Optional<AuthenticationResult> post(Request request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        return request;
    }
}
