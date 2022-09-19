package org.entando.entando.keycloak.servlet;

import com.agiletec.aps.system.RequestContext;
import com.agiletec.aps.system.services.lang.Lang;
import com.agiletec.aps.system.services.page.IPage;
import com.agiletec.aps.system.services.page.IPageManager;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.entando.entando.ent.exception.EntException;
import org.entando.entando.ent.util.EntLogging.EntLogFactory;
import org.entando.entando.ent.util.EntLogging.EntLogger;
import org.entando.entando.plugins.jacms.aps.servlet.ProtectedResourceProvider;

/**
 * @author E.Santoboni
 */
public class KcProtectedResourceProvider extends ProtectedResourceProvider {

    private static final EntLogger logger = EntLogFactory.getSanitizedLogger(KcProtectedResourceProvider.class);
    
    private boolean enabled;
    
    @Override
    protected void executeLoginRedirect(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        try {
            if (!this.isEnabled()) {
                super.executeLoginRedirect(request, response);
                return;
            }
            Lang defaultLang = this.getLangManager().getDefaultLang();
            String redirectParam = request.getParameter(RequestContext.PAR_REDIRECT_FLAG);
            if (redirectParam == null || "".equals(redirectParam)) {
                StringBuilder targetUrl = new StringBuilder(request.getRequestURL());
                targetUrl.append("?");
                String queryString = request.getQueryString();
                if (null != queryString && queryString.trim().length() > 0) {
                    targetUrl.append(queryString).append("&");
                }
                targetUrl.append(RequestContext.PAR_REDIRECT_FLAG).append("=1");
                String kcEntryPoint = this.getUrlManager().getApplicationBaseURL(request);
                if (!kcEntryPoint.endsWith("/")) {
                    kcEntryPoint += "/";
                }
                kcEntryPoint += "do/login?redirectTo=" + URLEncoder.encode(targetUrl.toString(), "UTF-8");
                response.sendRedirect(kcEntryPoint);
            } else {
                this.returnUserNotAuthorized(defaultLang, request, response);
            }
        } catch (Throwable t) {
            logger.error("Error executing redirect login page", t);
            throw new ServletException("Error executing redirect login page", t);
        }
    }

    protected void returnUserNotAuthorized(Lang defaultLang, HttpServletRequest request, HttpServletResponse response) throws IOException, EntException {
        Map<String, String> params = new HashMap<>();
        params.put("userUnauthorized", Boolean.TRUE.toString());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String errorPageCode = this.getPageManager().getConfig(IPageManager.CONFIG_PARAM_ERROR_PAGE_CODE);
        IPage errorPage = this.getPageManager().getOnlinePage(errorPageCode);
        String url = this.getUrlManager().createURL(errorPage, defaultLang, params, false, request);
        response.sendRedirect(url);
    }

    protected boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

}
