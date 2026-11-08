# Sustenaut sign-in: Keycloak with the ADORSYS OpenID4VP (wallet) plugin and our own
# providers (extension/) baked in.
#
# The plugin is built from a pinned commit with our patches (plugin-patches/) applied.
# The commit is the head of upstream PR #210 ("import verified external users"),
# because the released v1.4.0 can only sign in users that already exist. The plugin
# is AGPL-3.0: the patches are also served from the login page (themes/sustenaut).

ARG KEYCLOAK_VERSION=26.8.0

FROM docker.io/library/maven:3.9-eclipse-temurin-21 AS plugin
ARG PLUGIN_REPO=https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin.git
ARG PLUGIN_COMMIT=a29bdc51b6d23071690caed03b60a33e928e5c8d
WORKDIR /src
COPY plugin-patches/ /patches/
RUN git init -q . \
 && git fetch -q --depth 1 "$PLUGIN_REPO" "$PLUGIN_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$PLUGIN_COMMIT" \
 && git apply /patches/*.patch
RUN --mount=type=cache,target=/root/.m2 \
    mvn -q -B package -DskipTests -Drevision=0.0.0-${PLUGIN_COMMIT} \
 && cp target/keycloak-oid4vp-plugin-0.0.0-${PLUGIN_COMMIT}.jar /oid4vp-plugin.jar

FROM docker.io/library/maven:3.9-eclipse-temurin-21 AS extension
WORKDIR /src
COPY extension/pom.xml .
COPY extension/src/ src/
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package

# dnsjava (BSD-3-Clause): app registration asks a domain's nameservers directly, over TCP.
FROM docker.io/library/maven:3.9-eclipse-temurin-21 AS dnsjava
ARG DNSJAVA_VERSION=3.6.5
ARG DNSJAVA_SHA256=d1208e39e4ba17ec643ac5832b8b17dcaf5e3ae28f8c65904a755e23523cd94a
RUN curl -fsSL -o /dnsjava.jar "https://repo1.maven.org/maven2/dnsjava/dnsjava/${DNSJAVA_VERSION}/dnsjava-${DNSJAVA_VERSION}.jar" \
 && echo "${DNSJAVA_SHA256}  /dnsjava.jar" | sha256sum -c -

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS build
# One instance, no cluster: caches stay local (sessions are in the database).
ENV KC_DB=postgres \
    KC_FEATURES=oid4vc-vci,oid4vc-vci-preauth-code \
    KC_HEALTH_ENABLED=true \
    KC_CACHE=local
COPY --from=plugin /oid4vp-plugin.jar /opt/keycloak/providers/oid4vp-plugin.jar
COPY --from=extension /src/target/sustenaut-keycloak.jar /opt/keycloak/providers/sustenaut-keycloak.jar
COPY --from=dnsjava /dnsjava.jar /opt/keycloak/providers/dnsjava.jar
COPY themes/ /opt/keycloak/themes/
COPY plugin-patches/ /opt/keycloak/themes/sustenaut/login/resources/plugin-source/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
COPY --from=build /opt/keycloak/ /opt/keycloak/
COPY --chmod=755 docker-entrypoint.sh /opt/keycloak/bin/sustenaut-entrypoint.sh
ENV KC_DB=postgres \
    KC_FEATURES=oid4vc-vci,oid4vc-vci-preauth-code \
    KC_HEALTH_ENABLED=true \
    KC_CACHE=local
ENTRYPOINT ["/opt/keycloak/bin/sustenaut-entrypoint.sh"]
CMD ["start", "--optimized"]
