/*
 * Copyright 2022-Present Entando Inc. (http://www.entando.com) All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */
package org.entando.entando.keycloak.services.control;

import com.agiletec.aps.system.RequestContext;
import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.services.controller.ControllerManager;
import com.agiletec.aps.system.services.controller.control.RequestAuthorizator;
import com.agiletec.aps.system.services.page.IPage;
import com.agiletec.aps.system.services.page.IPageManager;
import com.agiletec.aps.system.services.user.UserDetails;
import java.net.URLEncoder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.entando.entando.ent.exception.EntException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KcRequestAuthorizator extends RequestAuthorizator {

    private static final Logger logger = LoggerFactory.getLogger(KcRequestAuthorizator.class);

    private boolean enabled;

    @Override
    public int service(RequestContext reqCtx, int status) {
        if (!this.isEnabled()) {
            return super.service(reqCtx, status);
        }
        logger.debug("Invoked: {}", this.getClass().getName());
        if (status == ControllerManager.ERROR) {
            return status;
        }
        int retStatus = ControllerManager.INVALID_STATUS;
        try {
            HttpServletRequest req = reqCtx.getRequest();
            HttpSession session = req.getSession();
            IPage currentPage = (IPage) reqCtx.getExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE);
            UserDetails currentUser = (UserDetails) session.getAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER);
            if (null == currentUser) {
                throw new EntException("no user on session");
            }
            boolean authorized = this.getAuthManager().isAuth(currentUser, currentPage);
            if (authorized) {
                retStatus = ControllerManager.CONTINUE;
            } else if (!currentUser.getUsername().equalsIgnoreCase(SystemConstants.GUEST_USER_NAME)) {
                return this.returnUserNotAuthorized(reqCtx);
            } else {
                StringBuilder targetUrl = new StringBuilder(req.getRequestURL());
                targetUrl.append("?");
                String queryString = req.getQueryString();
                if (null != queryString && queryString.trim().length() > 0) {
                    targetUrl.append(queryString).append("&");
                }
                targetUrl.append(RequestContext.PAR_REDIRECT_FLAG).append("=1");
                String kcEntryPoint = this.getUrlManager().getApplicationBaseURL(req);
                if (!kcEntryPoint.endsWith("/")) {
                    kcEntryPoint += "/";
                }
                kcEntryPoint += "do/login?redirectTo=" + URLEncoder.encode(targetUrl.toString(), "UTF-8");
                retStatus = this.redirectKcUrl(kcEntryPoint, reqCtx);
            }
        } catch (Exception t) {
            logger.error("Error while processing the request", t);
            retStatus = ControllerManager.SYS_ERROR;
            reqCtx.setHTTPError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        return retStatus;
    }

    protected int redirectKcUrl(String urlDest, RequestContext reqCtx) {
        int retStatus;
        try {
            String redirPar = this.getParameter(RequestContext.PAR_REDIRECT_FLAG, reqCtx);
            if (redirPar == null || "".equals(redirPar)) {
                reqCtx.clearError();
                reqCtx.addExtraParam(RequestContext.EXTRAPAR_REDIRECT_URL, urlDest);
                retStatus = ControllerManager.REDIRECT;
            } else {
                return this.returnUserNotAuthorized(reqCtx);
            }
        } catch (Exception t) {
            retStatus = ControllerManager.SYS_ERROR;
            reqCtx.setHTTPError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            logger.error("Error on creation redirect to url {}", urlDest, t);
        }
        return retStatus;
    }

    protected int returnUserNotAuthorized(RequestContext reqCtx) {
        reqCtx.getRequest().setAttribute("userUnauthorized", true);
        reqCtx.setHTTPError(HttpServletResponse.SC_UNAUTHORIZED);
        reqCtx.getResponse().setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String errorPageCode = this.getPageManager().getConfig(IPageManager.CONFIG_PARAM_ERROR_PAGE_CODE);
        IPage errorPage = this.getPageManager().getOnlinePage(errorPageCode);
        reqCtx.addExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE, errorPage);
        return ControllerManager.CONTINUE;
    }

    protected boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

}
