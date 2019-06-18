# Shibboleth IdP Social User authentication extensions

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/mpassid/shibboleth-idp-authn-socialuser.svg?branch=master)](https://travis-ci.org/mpassid/shibboleth-idp-authn-socialuser)
[![Coverage Status](https://coveralls.io/repos/github/mpassid/shibboleth-idp-authn-socialuser/badge.svg?branch=master)](https://coveralls.io/github/mpassid/shibboleth-idp-authn-socialuser?branch=master)

## Overview
For most parts this module is not actively maintained. Do not use it to extend your shibboleth idp except for experimental purposes. 
This module contains implementations of Facebook, Google, LinkedIn, Twitter, Yle, OAuth2 and OpenID Connect authentication modules for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home).

## Authentication modules

### Authentication concerns
- By their very nature, these modules do create (if not pre-existing) a authenticated session to the social identity provider. Logging out of SP or IdP does not logout user from the social identity provider. 
- Not all of these modules support forced authentication. We interpret forced authentication here as already authenticated user requiring to enter credentials to social identity provider for reauthentication. We hope to add that to as many as we can. The case of not using forced authentication combined with a browser shared by many is problematic. In such cases users must be instructed to use private browsing and to close that browser in the end. 

### Spring Social modules
There are four modules implemented using Spring Social.  

#### Attributes
Spring social modules all try to populate email, firstName, lastName, userId, displayName and providerId. In successful authentication case userId is always populated. See examples in attribute-resolver.xml on how to read them from SocialUserContext.

#### Facebook
- Template for bean definition in socialuser-authn-beans.xml: FacebookIdentity
- This module supports forced authentication.

#### Google
- Template for bean definition in socialuser-authn-beans.xml: GoogleIdentity
- This module does not support forced authentication.
- As Google support OpenID Connect, you can use the generic OpenID Connect flow instead. See OpenID Connect section below.

#### LinkedIn
- Template for bean definition in socialuser-authn-beans.xml: LinkedInIdentity
- This module does not support forced authentication.

#### Twitter
- Template for bean definition in socialuser-authn-beans.xml: TwitterIdentity
- This module supports forced authentication.

### Nimbus modules
There are three modules implemented using Nimbus OAuth2 SDK.  

#### Attributes
All Nimbus based modules have population of principals configured in the respective beans (see the examples in socialuser-authn-beans.xml). Which claims are which principals is configured with claimsPrincipals-property. If you want a claim to be interpreted as (json)array you need to instruct that with customClaimsTypes-property. If you name the principals as other than email, firstName, lastName, userId, displayName or providerId, you will need to read the values from principal map. Also, if the claim is an array having more than one field, the only way to read all fields is by principal map.

#### OAuth2 
- Template for bean definition in socialuser-authn-beans.xml: ExampleOauth2Identity
- This module does not support forced authentication by default.
- Windows Live ID example configuration in socialuser-authn-beans.xml.

#### OpenID Connect
- Example flow exists in _src/main/resources/flows/authn/socialuseropenidconnect-authn-flow.xml_.
- This module maybe be configured to support forced auhentication, passive authentication and login hint.
- Forced authentication request is implemented as max_age=0 oidc parameter. Not all providers respect that.
- Passive authentication request is implemented prompt=none oidc parameter. Check that the provider respects that.
- Login hint is implemented as login_hint oidc paramter. See example flow in socialuseropenidconnectloginhint-authn-flow.xml

#### Yle (Finnish Broadcasting Company)
- Template for bean definition in socialuser-authn-beans.xml: OAuth2YleIdentity
- This module does not support forced authentication.


## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

After successful compilation, the _target_ directory contains _shibboleth-idp-authn-socialuser-\<version\>.zip_ archive.

## Deployment

After compilation, the module's JAR files must be deployed to the IdP Web application and it must be configured. Depending on the IdP installation, the module deployment may be achieved for instance with the following sequence:

```
unzip shibboleth-idp-authn-socialuser-<version>.zip
cp shibboleth-idp-authn-socialuser-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib/.
cd /opt/shibboleth-idp
sh bin/build.sh
cp -r shibboleth-idp-authn-socialuser-<version>/conf /opt/shibboleth-idp/conf
cp -r shibboleth-idp-authn-socialuser-<version>/flows /opt/shibboleth-idp/flows
cp -r shibboleth-idp-authn-socialuser-<version>/views /opt/shibboleth-idp/views
```

The second final command will rebuild the _war_-package for the IdP application.

The copied bean definitions will need to be configured. 

1. You will need to define the OAuth parameters for the  authentication beans defined in /opt/shibboleth-idp/flows/authn/SocialUser/socialuser-authn-beans.xml. The activated beans will need to be mapped in SocialUserImplementationFactory bean defined in the same file. Remove mappings that you are not using.
2. You will need to add the new authentication flow(s) to /opt/shibboleth-idp/conf/authn/general-authn.xml. The following snippet is only an example, your version may be different depending on which authentication flows you have decided to support. See /opt/shibboleth-idp/flows for available SocialUser flows. It makes sense to create new properly named flows atleast in the cases of adopting generic oauth2/oidc flow examples.

```
<bean id="authn/SocialUserTwitter" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
<bean id="authn/SocialUserFacebook" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>       
<bean id="authn/SocialUserGoogle" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" />
<bean id="authn/SocialUserLinkedIn" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" />
<bean id="authn/SocialUserLiveID" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" />            
```

3. Add following Social User event ids to /opt/shibboleth-idp/conf/authn/authn-events-flow.xml 

```
<end-state id="SocialUserException" />
<end-state id="SocialUserCanceled" />

```

4. Add following error mappings to /opt/shibboleth-idp/conf/errors.xml section shibboleth.SAML2StatusMappings

```
<util:map id="shibboleth.SAML2StatusMappings">
        <entry key="SocialUserException" value-ref="shibboleth.SAML2Status.AuthnFailed" />
        <entry key="SocialUserCanceled" value-ref="shibboleth.SAML2Status.AuthnFailed" />

```

5. /opt/shibboleth-idp/conf/attribute-resolver-social.xml has some example attribute definitions. 

6. New authentication flow(s) can now be used by enabling it in idp.properties file
