FROM entando/entando-wildfly12-base:6.1.5
COPY target/*.war /wildfly/standalone/deployments/
RUN $ENTANDO_COMMON_PATH/init-derby-from-war.sh