#!/bin/sh
# Applies the realms with keycloak-config-cli: first sustenaut.json, family.json and team.json
# (and, locally, the dev clients), then master.json in a run of its own. master.json moves the
# master realm to the admin console's address (not public). The first time it
# does, the run's own admin token was issued under the old address and stops
# working, so that run ends with 401 after the change is made; a second run, with
# a fresh token, then finds nothing to change. Hence the one retry.
set -e
# shellcheck disable=SC2086 # JAVA_OPTS is a list of options
java $JAVA_OPTS -jar /app/keycloak-config-cli.jar
export IMPORT_FILES_LOCATIONS=/config/master.json
# shellcheck disable=SC2086
java $JAVA_OPTS -jar /app/keycloak-config-cli.jar || exec java $JAVA_OPTS -jar /app/keycloak-config-cli.jar
