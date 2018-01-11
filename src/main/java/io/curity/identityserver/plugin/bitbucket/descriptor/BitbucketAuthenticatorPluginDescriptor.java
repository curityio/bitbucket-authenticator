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

package io.curity.identityserver.plugin.bitbucket.descriptor;

import io.curity.identityserver.plugin.bitbucket.authentication.BitbucketAuthenticatorRequestHandler;
import io.curity.identityserver.plugin.bitbucket.authentication.CallbackRequestHandler;
import io.curity.identityserver.plugin.bitbucket.config.BitbucketAuthenticatorPluginConfig;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticatorPluginDescriptor;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class BitbucketAuthenticatorPluginDescriptor
        implements AuthenticatorPluginDescriptor<BitbucketAuthenticatorPluginConfig>
{
    public final static String CALLBACK = "callback";

    @Override
    public String getPluginImplementationType()
    {
        return "bitbucket";
    }

    @Override
    public Class<? extends BitbucketAuthenticatorPluginConfig> getConfigurationType()
    {
        return BitbucketAuthenticatorPluginConfig.class;
    }

    @Override
    public Map<String, Class<? extends AuthenticatorRequestHandler<?>>> getAuthenticationRequestHandlerTypes()
    {
        Map<String, Class<? extends AuthenticatorRequestHandler<?>>> handlers = new LinkedHashMap<>(2);
        handlers.put("index", BitbucketAuthenticatorRequestHandler.class);
        handlers.put(CALLBACK, CallbackRequestHandler.class);

        return Collections.unmodifiableMap(handlers);
    }

}
