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

package io.curity.identityserver.plugin.bitbucket.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface BitbucketAuthenticatorPluginConfig extends Configuration
{
    @Description("Consumer key")
    String getClientId();

    @Description("Consumer secret of the client application")
    String getClientSecret();

    @Description("Get list of teams the user is a member of")
    @DefaultBoolean(false)
    boolean isGetTeams();

    @Description("Get list of repositories the user has access to")
    @DefaultBoolean(false)
    boolean isGetRepositories();

    @Description("Get user account information as well as email")
    @DefaultBoolean(false)
    boolean isGetAccountInformation();

    @Description("Get the users email address")
    @DefaultBoolean(true)
    boolean isGetEmails();

    @Description("The name of the team the user must be a part of to login")
    Optional<String> getTeamName();

    enum Access
    {
        NONE, READ, WRITE
    }

    @Description("Manage access to all the repositories the authorizing user has access to")
    @DefaultEnum("NONE")
    Access getRepositoryAccess();

    @Description("Request a scope (repository:admin) that gives the app admin access to all the repositories the authorizing user has access to. It gives access to the admin features of a repo only, not direct access to its contents")
    @DefaultBoolean(false)
    boolean isRepositoryAdmin();

    @Description("Manage access to all the snippets the authorizing user has access to")
    @DefaultEnum("NONE")
    Access getSnippetAccess();

    @Description("Manage ability to interact with issue trackers")
    @DefaultEnum("NONE")
    Access getIssueAccess();

    @Description("Request a scope (wiki) that gives access to wiki's")
    @DefaultBoolean(false)
    boolean isWikiAccess();

    @Description("Manage access to pull requests and collaborate on them")
    @DefaultEnum("NONE")
    Access getPullRequestAccess();

    @Description("Manage ability to see and change all the user’s account information")
    @DefaultEnum("NONE")
    Access getAccountAccess();

    @Description("Manage team access")
    @DefaultEnum("NONE")
    Access getTeamAccess();

    @Description("Request a scope (webhook) that gives access to webhooks")
    @DefaultBoolean(false)
    boolean isWebhookAccess();


    @Description("The HTTP client with any proxy and TLS settings that will be used to connect to slack")
    Optional<HttpClient> getHttpClient();

    SessionManager getSessionManager();

    ExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    Json getJson();

}
