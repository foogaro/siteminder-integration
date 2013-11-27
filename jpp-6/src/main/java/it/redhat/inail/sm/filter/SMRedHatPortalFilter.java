package it.redhat.inail.sm.filter;

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;

import static it.redhat.inail.sm.Const.*;

/**
 * @author lfugaro@redhat.com
 */
@WebFilter(filterName = "SMRedHatPortalFilter", urlPatterns = "/*")
public class SMRedHatPortalFilter extends AbstractFilter {

    private static final Log logger = ExoLogger.getLogger(SMRedHatPortalFilter.class);

    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;

        if (needToLogin(request, response)) {
            String requestURI = request.getRequestURI();
            logger.debug("requestURI: " + requestURI);
            requestURI = URLEncoder.encode(requestURI, UTF8);
            logger.debug("requestURI-encoded: " + requestURI);
            response.sendRedirect(SM_PORTAL_LOGIN + QS + INITIAL_URI + QS_EQ + requestURI);
            return;
        }
        chain.doFilter(req, resp);
    }

    private boolean needToLogin(HttpServletRequest request, HttpServletResponse response) {
        String remoteUser = request.getRemoteUser();
        Principal userPrincipal = request.getUserPrincipal();
        String referer = request.getHeader(HTTP_HEADER_REFERER);
        String requestURL = request.getRequestURL().toString();

        if (logger.isDebugEnabled()) {
            logger.debug("remoteUser: " + remoteUser);
            logger.debug("userPrincipal: " + userPrincipal);
            logger.debug("referer: " + referer);
            logger.debug("requestURL: " + requestURL);
        }

        if (userPrincipal == null && (requestURL == null || !requestURL.contains(SM_PORTAL_LOGIN))) {
            return Boolean.TRUE;
        }

        return Boolean.FALSE;
    }

}
