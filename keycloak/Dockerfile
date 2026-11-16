FROM maven:3.9-eclipse-temurin-21 AS provider
WORKDIR /build
COPY bcrypt-provider/pom.xml .
RUN mvn -B -q dependency:go-offline
COPY bcrypt-provider/src ./src
RUN mvn -B -q package -DskipTests

FROM quay.io/keycloak/keycloak:26.8.1 AS builder
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
COPY --from=provider /build/target/keycloak-bcrypt-provider.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.8.1
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY realm/ /opt/keycloak/data/import/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized", "--import-realm"]
