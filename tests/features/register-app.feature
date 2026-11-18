Feature: register-app.py --site-status
  Against a stand-in for auth.sustenaut.eu, one scenario per outcome. The site is
  https://site.example.org on the client example.org of the realm team, its redirect
  /oauth2/callback, its logout / and its role "site"; the registration is in state/client.json.

  Background:
    Given a scratch directory
    And a file "state/client.json" holding "{"client_id": "example.org", "client_secret": "secret-1", "registration_access_token": "token-1"}"
    And a fake "keycloak" service

  Scenario: A site whose uris and role are on the client is present
    Given the "keycloak" service answers "GET /realms/team/clients-registrations/default/example.org" with 200 and:
      """
      {"redirectUris": ["https://site.example.org/oauth2/callback"],
       "attributes": {"post.logout.redirect.uris": "https://site.example.org/"}}
      """
    And the "keycloak" service answers "POST /realms/team/app-registration/example.org/roles" with 200 and:
      """
      {"roles": ["other", "site"]}
      """
    When the site's status is asked of the "keycloak" service
    Then the exit code is 0
    And it prints:
      """
      redirect https://site.example.org/oauth2/callback: present
      logout https://site.example.org/: present
      role site: present
      """
    And the "keycloak" service was asked "GET /realms/team/clients-registrations/default/example.org" with the header "Authorization" set to "Bearer token-1"
    And the "keycloak" service was sent:
      """
      {"roles": []}
      """

  Scenario: A missing redirect is said
    Given the "keycloak" service answers "GET /realms/team/clients-registrations/default/example.org" with 200 and:
      """
      {"redirectUris": ["https://other.example.org/oauth2/callback"],
       "attributes": {"post.logout.redirect.uris": "https://site.example.org/"}}
      """
    And the "keycloak" service answers "POST /realms/team/app-registration/example.org/roles" with 200 and:
      """
      {"roles": ["site"]}
      """
    When the site's status is asked of the "keycloak" service
    Then the exit code is 1
    And it prints "redirect https://site.example.org/oauth2/callback: missing"

  Scenario: A missing role is said
    Given the "keycloak" service answers "GET /realms/team/clients-registrations/default/example.org" with 200 and:
      """
      {"redirectUris": ["https://site.example.org/oauth2/callback"],
       "attributes": {"post.logout.redirect.uris": "https://site.example.org/"}}
      """
    And the "keycloak" service answers "POST /realms/team/app-registration/example.org/roles" with 200 and:
      """
      {"roles": ["other"]}
      """
    When the site's status is asked of the "keycloak" service
    Then the exit code is 1
    And it prints "role site: missing"

  Scenario: No state file is unreadable
    Given the file "state/client.json" is removed
    When the site's status is asked of the "keycloak" service
    Then the exit code is 2
    And it prints a line matching "no registration: */state/client.json is not there"
    And the "keycloak" service was asked nothing

  Scenario: A client that does not answer its token is unreadable
    Given the "keycloak" service answers "GET /realms/team/clients-registrations/default/example.org" with 401
    When the site's status is asked of the "keycloak" service
    Then the exit code is 2
    And it prints:
      """
      the client example.org does not answer to its registration token (HTTP 401)
      """

  Scenario: A new registration token is kept and none is printed
    Given the "keycloak" service answers "GET /realms/team/clients-registrations/default/example.org" with 200 and:
      """
      {"redirectUris": ["https://site.example.org/oauth2/callback"],
       "attributes": {"post.logout.redirect.uris": "https://site.example.org/"},
       "registrationAccessToken": "token-2"}
      """
    And the "keycloak" service answers "POST /realms/team/app-registration/example.org/roles" with 200 and:
      """
      {"roles": ["site"]}
      """
    When the site's status is asked of the "keycloak" service
    Then the JSON in "state/client.json" has "registration_access_token" equal to "token-2"
    And the directory "state" holds:
      """
      client.json
      """
    And the file "state/client.json" is readable and writable by its owner alone
    And it does not print "token"
    And it does not print "secret"
