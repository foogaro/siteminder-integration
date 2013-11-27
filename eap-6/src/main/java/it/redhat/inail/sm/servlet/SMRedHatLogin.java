package it.redhat.inail.sm.servlet;

import it.redhat.inail.sm.SSOUtils;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author lfugaro@redhat.com
 */

@WebServlet(name="SMRedHatLogin", urlPatterns={"/login"})
public class SMRedHatLogin extends HttpServlet {

    protected void doPost(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws javax.servlet.ServletException, IOException {
        doGet(request, response);
    }

    protected void doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws javax.servlet.ServletException, IOException {

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

        String sm_user = SSOUtils.getSMUser();

        StringBuilder builder = new StringBuilder();

        builder.append("<HTML>");
        builder.append("<HEAD>");
        builder.append("<TITLE>-{" + System.currentTimeMillis() + "}-</TITLE>");
        builder.append("</HEAD>");
        builder.append("<BODY>");
        builder.append("<FORM style=\"display: none;\" METHOD=\"POST\" ACTION=\"" + getForwardpath(request) + "/j_security_check\">");
        builder.append("<INPUT TYPE=\"text\" NAME=\"j_username\"" + " VALUE=\"" + sm_user + "\"/>");
        builder.append("<INPUT TYPE=\"password\" NAME=\"j_password\"" + " VALUE=\"fake\"/>");
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
