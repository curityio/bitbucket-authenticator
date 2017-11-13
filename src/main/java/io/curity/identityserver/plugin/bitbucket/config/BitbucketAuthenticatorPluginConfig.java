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
import se.curity.identityserver.sdk.config.annotation.DefaultString;
import se.curity.identityserver.sdk.config.annotation.DefaultURI;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.SessionManager;

import java.net.URI;

@SuppressWarnings("InterfaceNeverImplemented")
public interface BitbucketAuthenticatorPluginConfig extends Configuration {
    @Description("Consumer key")
    String getClientId();

    @Description("Consumer secret used for communication with bitbucket")
    String getClientSecret();

    @Description("URL to the Bitbucket authorization endpoint")
    @DefaultURI("https://bitbucket.com/login/oauth/authorize")
    URI getAuthorizationEndpoint();

    @Description("URL to the Bitbucket token endpoint")
    @DefaultURI("https://bitbucket.org/site/oauth2/access_token")
    URI getTokenEndpoint();

    @Description("Get list of teams the user is a member of")
    @DefaultBoolean(false)
    Boolean isGetTeams();


    @Description("Get list of repositories the user has access to")
    @DefaultBoolean(false)
    Boolean isGetRepositories();

    @Description("Get user account information as well as email")
    @DefaultBoolean(false)
    Boolean isGetAccountInformation();

    @Description("Get the users email address")
    @DefaultBoolean(true)
    Boolean isGetEmails();

    @Description("The name of the team the user must be a part of to login")
    @DefaultString("")
    String getTeamName();

    SessionManager getSessionManager();

}