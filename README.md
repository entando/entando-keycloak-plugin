# Entando Keycloak Plugin
Keycloak Integration for Entando Core - Gives SSO capabilities and also has User Management through Keycloak.

## Scope

### What this plugin does
* Enables SSO capabilities to an Entando Instance by using Keycloak.
* Moves User Management to Keycloak.

### What this plugin does not
This plugin doesn't come with Role and Group management, because Entando Core roles/groups model isn't compatible with Keycloak. That means that even with the same users across multiple Entando Instances, the role and group mappings have to be configured on each instance.

## Installing

### Installing on your project
First add the `entando-keycloak-auth` dependency to your pom.xml

```
<dependency>
    <groupId>org.entando.entando</groupId>
    <artifactId>entando-keycloak-auth</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <type>war</type>
</dependency>

<!-- </required-by dependency="org.keycloak:keycloak-admin-client"> -->
<dependency>
    <groupId>org.jboss.resteasy</groupId>
    <artifactId>resteasy-client</artifactId>
    <version>3.0.18.Final</version>
</dependency>
<dependency>
    <groupId>org.jboss.resteasy</groupId>
    <artifactId>resteasy-jaxrs</artifactId>
    <version>3.0.18.Final</version>
</dependency>
<dependency>
    <groupId>org.jboss.resteasy</groupId>
    <artifactId>resteasy-jackson2-provider</artifactId>
    <version>3.6.3.Final</version>
</dependency>
<!-- </required-by> -->
```

#### Edit systemParams.properties

Then you have to open the `systemParams.properties` to add keycloak configuration

```
keycloak.authUrl=${KEYCLOAK_AUTH_URL:http://localhost:8081/auth}
keycloak.realm=${KEYCLOAK_REALM:entando-development}
keycloak.clientId=${KEYCLOAK_CLIENT_ID:entando-core}
keycloak.clientSecret=${KEYCLOAK_CLIENT_SECRET:930837f0-95b2-4eeb-b303-82a56cac76e6}
```

#### Edit web.xml

And finally you have to change the configuration on `web.xml` from
```
classpath:spring/web/servlet-context.xml
```

To 
```
classpath:spring/web/servlet-context-keycloak.xml
```

## Keycloak Setup
In order to setup keycloak to work with entando instance, please refer to the documentation here https://github.com/entando/entando-keycloak-plugin/wiki/Setup-Keycloak

## Known issues

### entando-plugin-jpinfinispan

Right now I detected some dependency issues with `entando-plugin-jpinfinispan`. In order to make it work along with this plugin, you have to add the following dependency to the `pom.xml` file.

```
<dependency>
    <groupId>org.jboss.logging</groupId>
    <artifactId>jboss-logging</artifactId>
    <version>3.3.0.Final</version>
</dependency>
```

### org.apache.log4j.spi.LoggerFactory

If you run this following exception:

```
Caused by: java.lang.NoClassDefFoundError: org/apache/log4j/spi/LoggerFactory
	at java.lang.Class.forName0(Native Method)
	at java.lang.Class.forName(Class.java:264)
	at org.owasp.esapi.util.ObjFactory.make(ObjFactory.java:74)
	at org.owasp.esapi.ESAPI.logFactory(ESAPI.java:137)
	at org.owasp.esapi.ESAPI.getLogger(ESAPI.java:154)
	at org.owasp.esapi.reference.DefaultEncoder.<init>(DefaultEncoder.java:75)
	at org.owasp.esapi.reference.DefaultEncoder.getInstance(DefaultEncoder.java:59)
	... 82 more
```

It might also be a dependency conflict, to fix this issue, add the following dependency to your `pom.xml` file.

```
<dependency>
    <groupId>log4j</groupId>
    <artifactId>log4j</artifactId>
    <version>1.2.17</version>
</dependency>
```

## Testing
Some tests are being tested with a real Keycloak instance so, in order to test, you have to start the keycloak before.

```
$ docker-compose -f keycloak/docker-compose.yml up -d
$ mvn test
```
