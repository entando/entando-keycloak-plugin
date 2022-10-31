package org.entando.entando.keycloak.services.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.agiletec.aps.BaseTestCase;
import com.agiletec.aps.system.RequestContext;
import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.services.controller.ControllerManager;
import com.agiletec.aps.system.services.controller.control.ControlServiceInterface;
import com.agiletec.aps.system.services.page.IPage;
import com.agiletec.aps.system.services.page.IPageManager;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author E.Santoboni
 */
class KcRequestAuthorizatorTest extends BaseTestCase {

    @Test
    void testService_1() throws Throwable {
        ((KcRequestAuthorizator) this.authorizator).setEnabled(false);
        this.executeTestService_1();
        ((KcRequestAuthorizator) this.authorizator).setEnabled(true);
        this.executeTestService_1();
    }

    private void executeTestService_1() throws Throwable {
        RequestContext reqCtx = this.getRequestContext();
        this.setUserOnSession(SystemConstants.GUEST_USER_NAME);
        IPage root = this.pageManager.getOnlineRoot();
        reqCtx.addExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE, root);
        int status = this.authorizator.service(reqCtx, ControllerManager.CONTINUE);
        assertEquals(ControllerManager.CONTINUE, status);
        String redirectUrl = (String) reqCtx.getExtraParam(RequestContext.EXTRAPAR_REDIRECT_URL);
        assertNull(redirectUrl);
    }

    @Test
    void testService_2() throws Throwable {
        RequestContext reqCtx = this.getRequestContext();
        this.setUserOnSession("admin");
        IPage root = this.pageManager.getOnlineRoot();
        reqCtx.addExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE, root);
        int status = this.authorizator.service(reqCtx, ControllerManager.CONTINUE);
        assertEquals(ControllerManager.CONTINUE, status);
        String redirectUrl = (String) reqCtx.getExtraParam(RequestContext.EXTRAPAR_REDIRECT_URL);
        assertNull(redirectUrl);
    }

    @Test
    void testServiceError() throws Throwable {
        RequestContext reqCtx = this.getRequestContext();
        int status = this.authorizator.service(reqCtx, ControllerManager.ERROR);
        assertEquals(ControllerManager.ERROR, status);
    }

    @Test
    void testServiceFailure_1() throws Throwable {
        RequestContext reqCtx = this.getRequestContext();
        ((MockHttpServletRequest) reqCtx.getRequest()).setRequestURI("/Entando/it/customers_page.page");
        ((MockHttpServletRequest) reqCtx.getRequest()).setQueryString("qsparamname=qsparamvalue");
        this.setUserOnSession(SystemConstants.GUEST_USER_NAME);
        IPage requiredPage = this.pageManager.getOnlinePage("customers_page");
        reqCtx.addExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE, requiredPage);
        int status = this.authorizator.service(reqCtx, ControllerManager.CONTINUE);
        assertEquals(ControllerManager.REDIRECT, status);
        String redirectUrl = (String) reqCtx.getExtraParam(RequestContext.EXTRAPAR_REDIRECT_URL);
        assertTrue(redirectUrl.contains("/Entando/do/login?"));
        assertTrue(redirectUrl.contains("redirectflag"));
        assertTrue(redirectUrl.contains("redirectTo="));
        assertTrue(redirectUrl.contains("customers_page.page"));
        assertTrue(redirectUrl.contains("qsparamname"));
        assertTrue(redirectUrl.contains("qsparamvalue"));
    }

    @Test
    void testServiceFailure_2() throws Throwable {
        RequestContext reqCtx = this.getRequestContext();
        reqCtx.getRequest().getSession().removeAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER);
        IPage root = this.pageManager.getOnlineRoot();
        reqCtx.addExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE, root);
        int status = this.authorizator.service(reqCtx, ControllerManager.CONTINUE);
        assertEquals(ControllerManager.SYS_ERROR, status);
    }

    @Test
    void testUserNotAuthorized() throws Throwable {
        RequestContext reqCtx = this.getRequestContext();
        ((MockHttpServletRequest) reqCtx.getRequest()).setRequestURI("/Entando/it/coach_page.page");
        this.setUserOnSession("editorCustomers");
        IPage requiredPage = this.pageManager.getOnlinePage("coach_page");
        reqCtx.addExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE, requiredPage);
        int status = this.authorizator.service(reqCtx, ControllerManager.CONTINUE);
        assertEquals(ControllerManager.CONTINUE, status);
        String redirectUrl = (String) reqCtx.getExtraParam(RequestContext.EXTRAPAR_REDIRECT_URL);
        assertNull(redirectUrl);
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, reqCtx.getResponse().getStatus());
        IPage currentPage = (IPage) reqCtx.getExtraParam(SystemConstants.EXTRAPAR_CURRENT_PAGE);
        assertEquals("errorpage", currentPage.getCode());
    }

    @BeforeEach
    private void init() throws Exception {
        try {
            this.authorizator = (ControlServiceInterface) this.getApplicationContext().getBean("RequestAuthorizatorControlService");
            this.pageManager = (IPageManager) this.getService(SystemConstants.PAGE_MANAGER);
            super.getRequestContext().removeExtraParam(RequestContext.EXTRAPAR_REDIRECT_URL);
            ((KcRequestAuthorizator) this.authorizator).setEnabled(true);
        } catch (Throwable e) {
            throw new Exception(e);
        }
    }

    private ControlServiceInterface authorizator;

    private IPageManager pageManager;

}
