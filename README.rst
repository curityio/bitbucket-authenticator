Bitbucket Authenticator Plugin
=============================

Bitbucket Oauth Authenticator plugin for the Curity Identity Server.

Create `Bitbucket app`_

Create Bitbucket Authenticator and configure following values.

Config
~~~~~~

+-------------------+--------------------------------------------------+-----------------------------+
| Name              | Default                                          | Description                 |
+===================+==================================================+=============================+
| ``Key``           |                                                  | Bitbucket app client id     |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Secret``        |                                                  | Bitbucket app secret key    |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Authorization`` | https://bitbucket.com/login/oauth/authorize      | URL to the Bitbucket        |
| ``Endpoint``      |                                                  | authorization endpoint      |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Token``         | https://bitbucket.org/site/oauth2/access_token   | URL to the Bitbucket        |
| ``Endpoint``      |                                                  | authorization endpoint      |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Get Teams``     |    ``false``                                     | Get list of teams the user  |
|                   |                                                  | is a member of              |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Get``           |    ``false``                                     | Get user account            |
| ``Account``       |                                                  | info  as well as email      |
| ``Information``   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Get``           |    ``false``                                     | Get list of repositories    |
| ``Repositories``  |                                                  | the user has access to      |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Get Emails``    |    ``true``                                      | Get the users email address |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Team Name``     |  ``optional``                                    | The name of the team the    |
|                   |                                                  | user must be a part of to   |
|                   |                                                  | login                       |
+-------------------+--------------------------------------------------+-----------------------------+

Build plugin
~~~~~~~~~~~~

First, collect credentials to the Curity Nexus, to be able to fetch the SDK. Add nexus credentials in maven settings.

Then, build the plugin by: ``mvn clean package``

Install plugin
~~~~~~~~~~~~~~

| To install a plugin into the server, simply drop its jars and all of
  its required resources, including Server-Provided Dependencies, in the
  ``<plugin_group>`` directory.
| Please visit `curity.io/plugins`_ for more information about plugin
  installation.

Required dependencies/jars
"""""""""""""""""""""""""""""""""""""

Following jars must be in plugin group classpath.

-  `commons-codec-1.9.jar`_
-  `commons-logging-1.2.jar`_
-  `google-collections-1.0-rc2.jar`_
-  `httpclient-4.5.jar`_
-  `httpcore-4.4.1.jar`_
-  `identityserver.plugins.authenticators-1.0.0.jar`_

Please visit `curity.io`_ for more information about the Curity Identity
Server.

.. _Bitbucket app: https://confluence.atlassian.com/bitbucket/oauth-on-bitbucket-cloud-238027431.html
.. _curity.io/plugins: https://support.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation
.. _commons-codec-1.9.jar: http://central.maven.org/maven2/commons-codec/commons-codec/1.9/commons-codec-1.9.jar
.. _commons-logging-1.2.jar: http://central.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar
.. _google-collections-1.0-rc2.jar: http://central.maven.org/maven2/com/google/collections/google-collections/1.0-rc2/google-collections-1.0-rc2.jar
.. _httpclient-4.5.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5/httpclient-4.5.jar
.. _httpcore-4.4.1.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.1/httpcore-4.4.1.jar
.. _identityserver.plugins.authenticators-1.0.0.jar: https://bitbucket.com/curityio/authenticator-plugin
.. _curity.io: https://curity.io/
