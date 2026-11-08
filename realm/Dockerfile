# The realm as code: keycloak-config-cli with realm/sustenaut.json, family.json,
# team.json and master.json baked in. Runs as the job auth-realm after each deploy (k8s/realm-job.yaml), and
# as the realm service in compose.yaml. $(env:NAME) placeholders in the files are
# filled from the job's environment.
FROM docker.io/adorsys/keycloak-config-cli:6.5.1-26.5.5
COPY sustenaut.json family.json team.json master.json /config/
COPY --chmod=755 apply-realm.sh /app/apply-realm.sh
ENV IMPORT_FILES_LOCATIONS=/config/sustenaut.json,/config/family.json,/config/team.json \
    IMPORT_VARSUBSTITUTION_ENABLED=true
ENTRYPOINT ["/app/apply-realm.sh"]
