@gate
Feature: The gate against a made-up Keycloak
  dev/prove_team.py runs these, then the gate against a real one under wrangler dev.

  Scenario: Signing in: code flow with PKCE and the client secret, back to the page asked for
    Then signing in: code flow with PKCE and the client secret, back to the page asked for

  Scenario: The cookie cannot be read or changed
    Then the cookie cannot be read or changed

  Scenario: A cookie made with another key is refused
    Then a cookie made with another key is refused

  Scenario: An unchanged hash asks userinfo nothing, and the hash is fetched once in 2 seconds
    Then an unchanged hash asks userinfo nothing, and the hash is fetched once in 2 seconds

  Scenario: The site's secret reaches the hash URL-encoded
    Then the site's secret reaches the hash URL-encoded

  Scenario: No requests, no calls: nothing runs by itself
    Then no requests, no calls: nothing runs by itself

  Scenario: The role is required, from userinfo
    Then the role is required, from userinfo

  Scenario: A role taken away is refused at the next request, the session going on
    Then a role taken away is refused at the next request, the session going on

  Scenario: Removed from all: refused at the next request, cookie gone
    Then removed from all: refused at the next request, cookie gone

  Scenario: A full check after 5 minutes even with the hash unchanged
    Then a full check after 5 minutes even with the hash unchanged

  Scenario: Keycloak down: reads go on, changes are refused, an out-of-date session is refused, sign-in waits
    Then Keycloak down: reads go on, changes are refused, an out-of-date session is refused, sign-in waits

  Scenario: The hash endpoint not set up counts as Keycloak unreachable
    Then the hash endpoint not set up counts as Keycloak unreachable

  Scenario: An expired session signs in again
    Then an expired session signs in again

  Scenario: ID tokens: wrong nonce, audience, issuer, signer or date are refused
    Then ID tokens: wrong nonce, audience, issuer, signer or date are refused

  Scenario: A callback without the flow's state signs nobody in
    Then a callback without the flow's state signs nobody in

  Scenario: No open redirect back from sign-in
    Then no open redirect back from sign-in

  Scenario: Behind the gate nothing may be kept by a shared cache
    Then behind the gate nothing may be kept by a shared cache

  Scenario: A site's own headers go on what it serves, and a public mark still becomes private
    Then a site's own headers go on what it serves, and a public mark still becomes private

  Scenario: A site's own handler answers past the check, null means the file, and it never runs before the check
    Then a site's own handler answers past the check, null means the file, and it never runs before the check

  Scenario: Fails closed without its settings; only /healthz is open
    Then fails closed without its settings; only /healthz is open
