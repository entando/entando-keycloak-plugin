FROM entando/entando-integration-tests-base:5.2.0
ARG MVN_COMMAND="mvn verify"
ENV MVN_COMMAND=$MVN_COMMAND
COPY . /usr/src/entando-keycloak-plugin
WORKDIR /usr/src/entando-keycloak-plugin/core
CMD $MVN_COMMAND