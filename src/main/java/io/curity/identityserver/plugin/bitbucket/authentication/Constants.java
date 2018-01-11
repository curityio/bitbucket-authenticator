package io.curity.identityserver.plugin.bitbucket.authentication;

public class Constants {
    public static final String ORGANIZATION_MEMBER_CHECK_URL = "https://api.bitbucket.com/orgs/";
    public static final String LOGIN = "login";
    public static final String SCOPE_TEAM = "team";
    public static final String SCOPE_REPOSITORY = "repository";
    public static final String SCOPE_ACCOUNT = "account";
    public static final String SCOPE_EMAIL = "email";
    public static final String REPOSITORIES = "repositories";
    public static final String USER = "user";
    public static final String USERNAME = "username";
    public static final String EMAILS = "emails";
    public static final String TEAMS = "teams";
    public static final String REFRESH_TOKEN = "refresh_token";

    private static final String BASE_URL = "https://api.bitbucket.org/";
    public static final String USER_PROFILE_URL = BASE_URL + "1.0/user";
    public static final String REPOSITORIES_URL = USER_PROFILE_URL + "/repositories";
    public static final String ACCOUNT_URL = BASE_URL + "1.0/users/";
    public static final String TEAMS_URL = BASE_URL + "2.0/teams?role=member";
    public static final String EMAILS_URL = ACCOUNT_URL + "/1.0/users/{accountname}/emails";

}
