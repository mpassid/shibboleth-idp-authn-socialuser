/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.mpass.shibboleth.authn.impl;

import java.util.Set;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal;
import fi.mpass.shibboleth.context.SocialUserContext;

/**
 * An action that extracts social user principals, creates a {@link SocialUserContext}, and attaches it to the
 * {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre
 * 
 *      <pre>
 *      ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null
 *      </pre>
 * 
 * @post If getHttpServletRequest() != null, a pair of form or query parameters is extracted to populate a
 *       {@link SocialUserContext}.
 */
@SuppressWarnings("rawtypes")
public class ExtractSocialPrincipalsFromSubject extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ExtractSocialPrincipalsFromSubject.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");
        final SocialUserContext suCtx = authenticationContext.getSubcontext(SocialUserContext.class, true);
        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.info("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        final Subject subject = authenticationContext.getSubcontext(ExternalAuthenticationContext.class).getSubject();
        final Set<SocialUserPrincipal> principals = subject.getPrincipals(SocialUserPrincipal.class);
        for (SocialUserPrincipal sprin : principals) {
            // Add all to map
            suCtx.addPrincipal(sprin.getType(), sprin.getValue());
            // Add specific principals
            SocialUserPrincipal.Types type = sprin.getTypesType();
            if (type == null) {
                continue;
            }
            switch (type) {
                /* These mapped values support only one principal value. */
                case providerId:
                    suCtx.setProviderId(sprin.getValue());
                    break;
                case userId:
                    suCtx.setUserId(sprin.getValue());
                    break;
                case email:
                    suCtx.setEmail(sprin.getValue());
                    break;
                case firstName:
                    suCtx.setFirstName(sprin.getValue());
                    break;
                case lastName:
                    suCtx.setLastName(sprin.getValue());
                    break;
                case displayName:
                    suCtx.setDisplayName(sprin.getValue());
                    break;
                default:
                    log.info("unmapped principal of type/value:" + sprin.getType() + "/" + sprin.getValue());
                    break;
            }
        }
        log.trace("Leaving");
        return;

    }

}
