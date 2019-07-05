#!/usr/bin/env bash
export MVN_COMMAND="mvn integration-test"
mvn clean package -DskipTests
docker-compose -f docker-compose-cicd.yml build
docker-compose -f docker-compose-cicd.yml up -d keycloak
docker-compose -f docker-compose-cicd.yml up entando-keycloak-test
docker cp $(docker ps -aq --filter ancestor=entando-keycloak-test:latest):/usr/src/entando-keycloak-plugin/core/target/site ./target/
docker cp $(docker ps -aq --filter ancestor=entando-keycloak-test:latest):/usr/src/entando-keycloak-plugin/core/target/surefire-reports ./core/target/
docker cp $(docker ps -aq --filter ancestor=entando-keycloak-test:latest):/usr/src/entando-keycloak-plugin/core/target/failsafe-reports ./core/target/
docker-compose -f docker-compose-cicd.yml down