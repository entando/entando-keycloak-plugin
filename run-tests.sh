#!/usr/bin/env bash
set -e
docker-compose -f docker-compose-cicd.yml build
docker-compose -f docker-compose-cicd.yml up -d keycloak
docker-compose -f docker-compose-cicd.yml up entando-keycloak-test
mkdir -p ./test-result
docker cp $(docker ps -aq --filter ancestor=entando-keycloak-test:latest):/usr/src/entando-keycloak-plugin/core/target ./core-docker-cicd-result/
docker-compose -f docker-compose-cicd.yml down