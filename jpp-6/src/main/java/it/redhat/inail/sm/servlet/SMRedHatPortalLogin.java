package it.redhat.inail.sm.servlet;

import it.redhat.inail.sm.SSOUtils;
import org.exoplatform.container.web.AbstractHttpServlet;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;

import static it.redhat.inail.sm.Const.*;


/**
 * @author lfugaro@redhat.com
 */
@WebServlet(name="SMRedHatPortalLogin", urlPatterns={"/smlogin"})
public class SMRedHatPortalLogin extends AbstractHttpServlet {

    private static final Log logger = ExoLogger.getLogger(SMRedHatPortalLogin.class);

    protected void doPost(HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws javax.servlet.ServletException, IOException {
        doGet(request, response);
    }

    protected void doGet(HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws javax.servlet.ServletException, IOException {

        logger.debug("Redirect to portal/login");

        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache, no-store");

        PrintWriter out = null;
        try {
            out = response.getWriter();
        } catch (IOException e) {
            e.printStackTrace();
            response.setStatus(400);
            return;
        }

        String sm_user = SSOUtils.getSMUser(request);
        logger.debug("sm_user: " + sm_user);

        StringBuilder builder = new StringBuilder();

        String initialURI = request.getParameter(INITIAL_URI);
        logger.debug("initialURI: " + initialURI);
        if (initialURI != null && initialURI.length()>0) {
            initialURI = URLDecoder.decode(initialURI, UTF8);
            logger.debug("initialURI-decode: " + initialURI);
            //FIXME: lato GateIn non avviene il decode della uri, per me e' la cipolla!
//            initialURI = URLEncoder.encode(initialURI, UTF8);
//            logger.debug("initialURI-encode: " + initialURI);
        } else {
            logger.warn("Login without: " + INITIAL_URI);
        }

        builder.append("<HTML>");
        builder.append("<HEAD>");
        builder.append("<TITLE>-{" + System.currentTimeMillis() + "}-</TITLE>");
        builder.append("</HEAD>");
        builder.append("<BODY>");
        builder.append("<FORM style=\"display: none;\" METHOD=\"POST\" ACTION=\"" + PORTAL_LOGIN + "\">");
        builder.append("<INPUT TYPE=\"text\" NAME=\"" + INITIAL_URI + "\"" + " VALUE=\"" + initialURI + "\"/>");
        builder.append("<INPUT TYPE=\"text\" NAME=\"username\"" + " VALUE=\"" + sm_user + "\"/>");
        builder.append("<INPUT TYPE=\"password\" NAME=\"password\"" + " VALUE=\"fake\"/>");
        builder.append("</FORM>");
        builder.append("<script type=\"text/javascript\">");
        builder.append("        document.forms[0].submit();");
        builder.append("</script>");
        builder.append("</BODY></HTML>");

        String str = builder.toString();
        out.println(str);
        out.close();

    }

    private String getForwardpath(HttpServletRequest rq){
        String context = rq.getServletContext().getContextPath();
        return context;
    }


}
