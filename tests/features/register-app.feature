Feature: register-app.py --site-status
  Against a stand-in for auth.sustenaut.eu, one scenario per outcome.

  Scenario: A site whose uris and role are on the client is present
    Then a site whose uris and role are on the client is present

  Scenario: A missing redirect is said
    Then a missing redirect is said

  Scenario: A missing role is said
    Then a missing role is said

  Scenario: No state file is unreadable
    Then no state file is unreadable

  Scenario: A client that does not answer its token is unreadable
    Then a client that does not answer its token is unreadable

  Scenario: A new registration token is kept and none is printed
    Then a new registration token is kept and none is printed
