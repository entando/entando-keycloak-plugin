# Entando Keycloak Plugin
Keycloak Integration for Entando Core - Gives SSO capabilities and also has User Management through Keycloak.

## Scope

### What this plugin does
Enables SSO capabilities to an Entando Instance by using Keycloak. Moves User Management to Keycloak.

### What this plugin does not
This plugin doesn't come with Role and Group management, because Entando Core roles/groups model isn't compatible with Keycloak.

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

Right now I detected some dependency issues with `entando-plugin-jpinfinispan` so, while I don't find a solution to this you have to disable this dependency on your project
