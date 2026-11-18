@gate
Feature: The gate against a made-up Keycloak
  dev/prove_team.py runs these, then the gate against a real one under wrangler dev.

  The site is https://pub.example behind the gate for the role "pub", its files answering
  "the page" marked "public, max-age=60". The made-up Keycloak signs anna@example.org in with
  the role "pub" and the access hash "h1". A browser keeps the cookies the gate sets, and the
  requests go to the site as the browser sends them.

  Background:
    Given a site behind the gate for the role "pub"

  Scenario: Signing in starts at the gate, keeping the page asked for
    When I GET "/some/page?x=1"
    Then the answer is 303
    And the answer's "Location" is "/oauth2/start?rd=%2Fsome%2Fpage%3Fx%3D1"

  Scenario: Signing in: code flow with PKCE, the flow kept in a cookie no script reads
    When the sign-in starts from "/some/page?x=1"
    Then the result's "authorize" is "https://auth.example/realms/team/protocol/openid-connect/auth"
    And the result's "code_challenge_method" is "S256"
    And the result's "redirect_uri" is "https://pub.example/oauth2/callback"
    And the result's "cookie" is '["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age"]'

  Scenario: Signing in: the client secret and the verifier, back to the page asked for
    When I sign in from "/some/page?x=1"
    Then the answer is 303
    And the answer's "Location" is "/some/page?x=1"
    And the result's "code_verifier sent" is "true"
    And the result's "session cookie" is '["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age"]'
    And the result's "refresh token in the cookie" is "false"

  Scenario: Signed in, the page is shown
    Given I have signed in at "/some/page?x=1"
    When I GET "/some/page?x=1"
    Then the answer is 200
    And the result's "text" is "the page"

  Scenario: The cookie cannot be read
    When I sign in from "/page"
    Then the result's "name in the sealed cookie" is "false"

  Scenario Outline: The cookie cannot be changed
    Given I have signed in at "/page"
    And the session cookie is <forged>
    When I GET "/page"
    Then the answer is 303
    And the answer's "Location" is "/oauth2/start?rd=%2Fpage"

    Examples:
      | forged                           |
      | its sealed part with a byte changed |
      | garbage                          |
      | its iv alone                     |
      | unsealed claims                  |

  Scenario: A cookie made with another key is refused
    Given I have signed in at "/page"
    And the setting "SESSION_KEY" is "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    When I GET "/page"
    Then the answer is 303

  Scenario: An unchanged hash asks userinfo nothing, and the hash is fetched once in 2 seconds
    Given I have signed in at "/page"
    And Keycloak's calls are counted from here
    And 3 seconds pass
    When I GET "/page" 5 times
    Then the result is "[200, 200, 200, 200, 200]"
    And Keycloak was asked for "userinfo" 0 times
    And Keycloak was asked for "access-state" 1 time

  Scenario: The site's secret reaches the hash URL-encoded
    Given I have signed in at "/page"
    And 3 seconds pass
    When I GET "/page"
    Then Keycloak was last asked for the hash with the header "Authorization" set to "Basic c3VzdGVuYXV0LmV1OnNlJTJGY3JldA=="

  Scenario: No requests, no calls: nothing runs by itself
    When the gate is made, and left alone
    Then Keycloak was asked nothing

  Scenario: The role is required, from userinfo
    Given Keycloak gives the role "release"
    And I have signed in at "/page"
    When I GET "/page"
    Then the answer is 403
    And the answer does not include "the page"

  Scenario: A role given lets in at the next request
    Given Keycloak gives the role "release"
    And I have signed in at "/page"
    And I have opened "/page"
    And Keycloak gives the role "pub"
    And Keycloak's access hash changes to "h2"
    And 3 seconds pass
    When I GET "/page"
    Then the answer is 200

  Scenario: A role taken away is refused at the next request, the session going on
    Given I have signed in at "/page"
    And I have opened "/page"
    And Keycloak gives the role "plan"
    And Keycloak's access hash changes to "h2"
    And 3 seconds pass
    When I GET "/page"
    Then the answer is 403

  Scenario: A refusal is kept in the cookie
    Given I have signed in at "/page"
    And Keycloak gives the role "plan"
    And Keycloak's access hash changes to "h2"
    And 3 seconds pass
    And I have opened "/page"
    And Keycloak's calls are counted from here
    When I GET "/page"
    Then the answer is 403
    And Keycloak was asked for "userinfo" 0 times

  Scenario: Removed from all: refused at the next request, cookie gone
    Given I have signed in at "/page"
    And the account is removed from Keycloak
    And Keycloak's access hash changes to "h2"
    And 3 seconds pass
    When I GET "/page"
    Then the answer is 303
    And the answer's "Location" is "/oauth2/start?rd=%2Fpage"
    And the browser keeps no session cookie

  Scenario: No full check before 5 minutes with the hash unchanged
    Given I have signed in at "/page"
    And Keycloak's calls are counted from here
    And 299 seconds pass
    When I GET "/page"
    Then the answer is 200
    And Keycloak was asked for "userinfo" 0 times

  Scenario: A full check after 5 minutes even with the hash unchanged
    Given I have signed in at "/page"
    And 299 seconds pass
    And I have opened "/page"
    And Keycloak's calls are counted from here
    And 2 seconds pass
    When I GET "/page"
    Then the answer is 200
    And Keycloak was asked for "userinfo" 1 time

  Scenario: Keycloak down: reads go on
    Given I have signed in at "/page"
    And Keycloak cannot be reached
    And 3 seconds pass
    When I GET "/page"
    Then the answer is 200

  Scenario: Keycloak down: changes are refused
    Given I have signed in at "/page"
    And Keycloak cannot be reached
    And 3 seconds pass
    When I send "POST" to "/page"
    Then the answer is 503

  Scenario: Keycloak down: a new isolate knows the last hash from the cache
    Given I have signed in at "/page"
    And Keycloak cannot be reached
    And 3 seconds pass
    And I have opened "/page"
    And a new isolate of the gate
    When I GET "/page"
    Then the answer is 200

  Scenario: Keycloak down: a session from before a change is refused
    Given I have signed in at "/page"
    And the session cookie is kept aside
    And Keycloak's access hash changes to "h2"
    And 3 seconds pass
    And I have opened "/page"
    And Keycloak cannot be reached
    And 3 seconds pass
    And the session cookie kept aside is put back
    When I GET "/page"
    Then the answer is 503

  Scenario: Keycloak down: sign-in waits
    Given Keycloak cannot be reached
    When I GET "/page"
    Then the answer is 303

  Scenario: The hash endpoint not set up counts as Keycloak unreachable for reads
    Given I have signed in at "/page"
    And the hash endpoint answers 503
    And 3 seconds pass
    When I GET "/page"
    Then the answer is 200

  Scenario: The hash endpoint not set up counts as Keycloak unreachable for changes
    Given I have signed in at "/page"
    And the hash endpoint answers 503
    And 3 seconds pass
    When I send "POST" to "/page"
    Then the answer is 503

  Scenario: An expired session signs in again
    Given I have signed in at "/page"
    And 8 days pass
    When I GET "/page"
    Then the answer is 303

  Scenario Outline: ID tokens: wrong nonce, audience, issuer, signer or date are refused
    Given Keycloak's ID tokens have the wrong <what>
    When I sign in from "/page"
    Then the answer is 400
    And the browser keeps no session cookie

    Examples:
      | what     |
      | audience |
      | issuer   |
      | date     |
      | nonce    |
      | signer   |

  Scenario: A callback without the flow's state signs nobody in
    When I GET "/oauth2/callback?code=c1&state=guess"
    Then the answer is 400
    And the browser keeps no session cookie

  Scenario Outline: No open redirect back from sign-in
    When I sign in from the gate's start, asked to go back to <where>
    Then the answer's "Location" is "/"

    Examples:
      | where                 |
      | another host          |
      | an absolute URL       |
      | a host after a backslash |
      | a relative path       |
      | a header of its own   |

  Scenario: Behind the gate nothing may be kept by a shared cache
    Given I have signed in at "/page"
    When I GET "/page"
    Then the answer's "Cache-Control" is "private, max-age=60"

  Scenario: A site's own headers go on what it serves, and a public mark still becomes private
    Given I have signed in at "/page"
    And the site sets its own headers
    When I GET "/page"
    Then the answer's "X-Frame-Options" is "DENY"
    And the answer's "X-Path" is "/page"
    And the answer's "Cache-Control" is "private, max-age=9"

  Scenario: A site's own handler never runs before the check
    Given the site has its own handler for "/own"
    When I GET "/own"
    Then the answer is 303
    And the site's handler was told:
      """
      []
      """

  Scenario: A site's own handler answers past the check
    Given the site has its own handler for "/own"
    And I have signed in at "/page"
    When I GET "/own"
    Then the result's "text" is "my page"
    And the answer's "X-Site" is "yes"
    And the answer's "Cache-Control" is "private, max-age=9"

  Scenario: A site's own handler's null means the file
    Given the site has its own handler for "/own"
    And I have signed in at "/page"
    When I GET "/file"
    Then the result's "text" is "the page"
    And the site's handler was told:
      """
      [{"email": "anna@example.org", "roles": ["pub"], "reading": false}]
      """

  Scenario: A site's own handler is told Keycloak can't be reached
    Given the site has its own handler for "/own"
    And I have signed in at "/page"
    And Keycloak cannot be reached
    And 3 seconds pass
    When I GET "/own"
    Then the answer is 200
    And the site's handler was told:
      """
      [{"email": "anna@example.org", "roles": ["pub"], "reading": true}]
      """

  Scenario: A site's own handler is not called without the role
    Given the site has its own handler for "/own"
    And I have signed in at "/page"
    And Keycloak gives the role "plan"
    And Keycloak's access hash changes to "h2"
    And 3 seconds pass
    When I GET "/own"
    Then the answer is 403
    And the site's handler was told:
      """
      []
      """

  Scenario Outline: Fails closed without its settings
    Given the setting "<name>" is missing
    When I GET "/page"
    Then the answer is 500

    Examples:
      | name          |
      | REALM_URL     |
      | CLIENT_ID     |
      | CLIENT_SECRET |
      | SESSION_KEY   |
      | ASSETS        |

  Scenario: Fails closed with a short session key
    Given the setting "SESSION_KEY" is "short"
    When I GET "/page"
    Then the answer is 500

  Scenario: Only /healthz is open
    When I GET "/healthz"
    Then the answer is 200

  Scenario: The gate needs its role
    When the gate is made with no settings
    Then it is refused, saying "role"
