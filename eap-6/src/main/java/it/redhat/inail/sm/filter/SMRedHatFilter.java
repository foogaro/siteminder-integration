package it.redhat.inail.sm.filter;

import org.jboss.logging.Logger;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Principal;

/**
 * @author lfugaro@redhat.com
 */
 @WebFilter(filterName = "SMRedHatFilter", urlPatterns = "/*")
public class SMRedHatFilter implements Filter {

    private Logger logger = Logger.getLogger(getClass().getName());

    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        String remoteUser = request.getRemoteUser();
        Principal userPrincipal = request.getUserPrincipal();

        if (logger.isDebugEnabled()) {
            logger.debug("remoteUser: " + remoteUser);
            logger.debug("userPrincipal: " + userPrincipal);
        }

        if (userPrincipal == null) {

        }
        chain.doFilter(req, resp);
    }

    public void init(FilterConfig config) throws ServletException {

    }

}
