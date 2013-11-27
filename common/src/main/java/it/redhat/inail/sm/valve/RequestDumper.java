package it.redhat.inail.sm.valve;

import it.redhat.inail.sm.RequestResponseHolder;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.jboss.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Enumeration;

/**
 * Questa classe e' utilizzata per salvare temporaneamente le Request e Response correnti per il Thread corrente.
 * Cio' consente ad altri oggetti nella "chain" di accedere alla Request e Response.
 * Ad esempio nel SMRedHatLoginModule.
 *
 * @author lfugaro@redhat.com
 */
public class RequestDumper extends ValveBase {

    private Logger logger = Logger.getLogger(getClass().getName());

    /**
     * Metodo invocato dal contenitore sel il Valve e' stato definito nel "context.xml" o "jboss-web.xml".
     * @param request Request
     * @param response Response
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        try {
            RequestResponseHolder.setRequestAndResponse(request, response);
            logger.debug("Saving Request and Response in ThreadLocal");

            if (logger.isDebugEnabled()) {
                // Log pre-service information
                logger.debug("REQUEST URI       =" + request.getRequestURI());
                logger.debug("          authType=" + request.getAuthType());
                logger.debug(" characterEncoding=" + request.getCharacterEncoding());
                logger.debug("     contentLength=" + request.getContentLength());
                logger.debug("       contentType=" + request.getContentType());
                logger.debug("       contextPath=" + request.getContextPath());
                Cookie cookies[] = request.getCookies();
                if (cookies != null) {
                    for (int i = 0; i < cookies.length; i++)
                        logger.debug("            cookie=" + cookies[i].getName() + "=" +
                                cookies[i].getValue());
                }
                Enumeration hnames = request.getHeaderNames();
                while (hnames.hasMoreElements()) {
                    String hname = (String) hnames.nextElement();
                    Enumeration hvalues = request.getHeaders(hname);
                    while (hvalues.hasMoreElements()) {
                        String hvalue = (String) hvalues.nextElement();
                        logger.debug("            header=" + hname + "=" + hvalue);
                    }
                }
                logger.debug("            locale=" + request.getLocale());
                logger.debug("            method=" + request.getMethod());
                Enumeration pnames = request.getParameterNames();
                while (pnames.hasMoreElements()) {
                    String pname = (String) pnames.nextElement();
                    String pvalues[] = request.getParameterValues(pname);
                    StringBuffer result = new StringBuffer(pname);
                    result.append('=');
                    for (int i = 0; i < pvalues.length; i++) {
                        if (i > 0)
                            result.append(", ");
                        result.append(pvalues[i]);
                    }
                    logger.debug("         parameter=" + result.toString());
                }
                logger.debug("          pathInfo=" + request.getPathInfo());
                logger.debug("          protocol=" + request.getProtocol());
                logger.debug("       queryString=" + request.getQueryString());
                logger.debug("        remoteAddr=" + request.getRemoteAddr());
                logger.debug("        remoteHost=" + request.getRemoteHost());
                logger.debug("        remoteUser=" + request.getRemoteUser());
                logger.debug("requestedSessionId=" + request.getRequestedSessionId());
                logger.debug("            scheme=" + request.getScheme());
                logger.debug("        serverName=" + request.getServerName());
                logger.debug("        serverPort=" + request.getServerPort());
                logger.debug("       servletPath=" + request.getServletPath());
                logger.debug("          isSecure=" + request.isSecure());
                logger.debug("---------------------------------------------------------------");
            }

            // Perform the request
            getNext().invoke(request, response);

            if (logger.isDebugEnabled()) {
                // Log post-service information
                logger.debug("---------------------------------------------------------------");
                logger.debug("          authType=" + request.getAuthType());
                logger.debug("     contentLength=" + response.getContentLength());
                logger.debug("       contentType=" + response.getContentType());
                Cookie rcookies[] = response.getCookies();
                for (int i = 0; i < rcookies.length; i++) {
                    logger.debug("            cookie=" + rcookies[i].getName() + "=" +
                            rcookies[i].getValue() + "; domain=" +
                            rcookies[i].getDomain() + "; path=" + rcookies[i].getPath());
                }
                Collection<String> rhnames = ((HttpServletResponse)response).getHeaderNames();
                for (String rhname : rhnames) {
                    String rhvalues[] = response.getHeaderValues(rhname);
                    for (int j = 0; j < rhvalues.length; j++)
                        logger.debug("            header=" + rhname + "=" + rhvalues[j]);
                }
                logger.debug("           message=" + response.getMessage());
                logger.debug("        remoteUser=" + request.getRemoteUser());
                logger.debug("            status=" + response.getStatus());
                logger.debug("===============================================================");
            }

        } finally {
            RequestResponseHolder.resetRequestAndResponse();
            logger.debug("Deleting Request and Response from ThreadLocal");
        }
    }
}
