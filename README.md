# Entando Keycloak Plugin
Keycloak Integration for Entando Core - Gives SSO capabilities and also has User Management through Keycloak.

For more information and documentation visit:  https://dev.entando.org, or https://forum.entando.org. Or for the latest news or product information please visit the main website: https://www.entando.com.

Information below is for building from source or running locally as a contributor or developer on the plugin itself.. See the links above for general documentation and usage.

## Scope

### What this plugin does
* Enables SSO capabilities to an Entando Instance by using Keycloak.
* Moves User Management to Keycloak.

### What this plugin does not
This plugin doesn't come with Role and Group management, because Entando Core roles/groups model isn't compatible with Keycloak. That means that even with the same users across multiple Entando Instances, the role and group mappings have to be configured on each instance.

## Properties
>- `keycloak.enabled`: Enables this plugin. (The default is `false`)
>- `keycloak.auth.url`: It's the Keycloak auth url. Example: `https://is.yourdomain.com/auth`. (The default is `http://localhost:8081/auth`)
>- `keycloak.realm`: The keycloak realm. See https://www.keycloak.org/docs/3.2/server_admin/topics/overview/concepts.html . (The default is `entando`)
>- `keycloak.client.id`: The keycloak confidential client id. (The default is `entando-app`)
>- `keycloak.client.secret`: The secret from the keycloak client. (The default is `<blank>`)
>- `keycloak.public.client.id`: The second keycloak client, this one must be public. (The default is `entando-web`)
>- `keycloak.secure.uris`: **[OPTIONAL]** Use if you want to secure an endpoint. Works with wildcards, comma separated.
>- `keycloak.authenticated.user.default.authorizations`: **[OPTIONAL]** Use if you want to automatically assign `group:role` to any user that logs in, comma separated. Example: `administrators:admin,readers`

## Installing

### Installing on your project
First add the `entando-keycloak-auth` dependency to your pom.xml

```xml
<dependency>
    <groupId>org.entando.entando</groupId>
    <artifactId>entando-keycloak-auth</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <type>war</type>
</dependency>
```

### Edit web.xml
To Oauth2 work properly, we have to replace the springDispatcher contextConfigLocation by replacing the regular `classpath:spring/web/servlet-context.xml` entry with the keycloak one `classpath:spring/web/servlet-context-keycloak.xml`,

Here what it should look like:

```xml
<servlet>
    <servlet-name>springDispatcher</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
    <init-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>classpath:spring/web/servlet-context-keycloak.xml</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
</servlet>
```

#### Edit systemParams.properties

Then you have to open the `systemParams.properties` to add keycloak configuration

```properties
keycloak.enabled=true
keycloak.auth.url=${KEYCLOAK_AUTH_URL:http://localhost:8081/auth}
keycloak.realm=${KEYCLOAK_REALM:entando-development}
keycloak.client.id=${KEYCLOAK_CLIENT_ID:entando-core}
keycloak.client.secret=${KEYCLOAK_CLIENT_SECRET:930837f0-95b2-4eeb-b303-82a56cac76e6}
keycloak.public.client.id=${KEYCLOAK_PUBLIC_CLIENT_ID:entando-web}
keycloak.secure.uris=/api/plugins/cms/contents/*/model/*,/api/pwa/notifications/*
keycloak.authenticated.user.default.authorizations=administrators:admin,readers
```

## Keycloak Setup
In order to setup keycloak to work with entando instance, please refer to the documentation here https://github.com/entando/entando-keycloak-plugin/wiki/Setup-Keycloak

## Keycloak Standard Flow
To enable the standard flow to keep sessions between Entando instances, please refer to the documentation here
https://github.com/entando/entando-keycloak-plugin/wiki/Enable-Standard-Flow-for-Keycloak-Login

## Known issues

### org.apache.log4j.spi.LoggerFactory

If you run this following exception:

```java
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

```xml
<dependency>
    <groupId>log4j</groupId>
    <artifactId>log4j</artifactId>
    <version>1.2.17</version>
</dependency>
```

## Testing
To run unit tests:
```
$ mvn test
```

Some tests are being tested with a real Keycloak instance so, in order to test, you have to start the keycloak before.
```
$ docker-compose -f keycloak/docker-compose.yml up -d
$ mvn failsafe:integration-test
```
