package it.redhat.inail.sm;

import org.jboss.logging.Logger;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import java.security.Principal;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static it.redhat.inail.sm.Const.*;

/**
 * @author lfugaro@redhat.com
 */
public class SSOUtils {

    private static Logger logger = Logger.getLogger(SSOUtils.class);

    /**
     * Metodo utilizzato per il recupero del SecurityContext.
     * @return Subject
     */
    public static Subject getSubject() {
        logger.debug("Getting Principal from SecurityContext");
        Subject caller = null;
        try {
            caller = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
        } catch (Throwable t) {
            logger.error("Errore: " +  t);
        }
        return caller;
    }

    /**
     * Metodo utilizzato per il recupero del Principal dal SecurityContext.
     * @return Principal
     */
    public static Principal getPrincipal() {
        logger.debug("Getting Principal from SecurityContext");
        Subject caller = null;
        try {
            caller = getSubject();
            if(caller!=null) {
                Set<Principal> principals = caller.getPrincipals();
                logger.debug("principals: " + principals);
                for(Principal principal : principals) {
                    logger.debug("principal: " + principal);
                    if(principal != null) {
                        logger.debug("principal: " + principal.getName());
                        if (principal instanceof Principal) {
                            return principal;
                        }
                    }
                }
            } else {
                logger.warn("SecurityContext not found");
            }
        } catch (Throwable t) {
            logger.error("Errore: {}", t);
        }
        return null;
    }

    /**
     * Metodo utilizzato per estrapolare il nome dell'utente contenuto nell'header HTTP "SM_USER".
     * @return valore header HTTP "SM_USER"
     */
    public static String getSMUser() {
        HttpServletRequest request = RequestResponseHolder.getRequest();
        return getSMUser(request);
    }

    /**
     * Metodo utilizzato per estrapolare il nome dell'utente contenuto nell'header HTTP "SM_USER".
     * @return valore header HTTP "SM_USER"
     */
    public static String getSMUser(HttpServletRequest request) {
        String sm_user = request.getHeader(SM_USER);
        logger.debug("sm_user: " + sm_user);

        if (sm_user == null || sm_user.trim().length() == 0) {
            logger.error("User not found");
            sm_user = System.getProperty("sm_user");
            if (sm_user == null || sm_user.trim().length() == 0) {
                throw new IllegalArgumentException("User not found");
            }
        }

        return sm_user.toLowerCase();
    }

    /**
     * Metodo utilizzato per estrapolare i ruoli dell'utente contenuti nell'header HTTP "SM_PRINCIPAL".
     * @return valore header HTTP "SM_PRINCIPAL"
     */
    public static String getSMPrincipal() {
        HttpServletRequest request = RequestResponseHolder.getRequest();
        return getSMPrincipal(request);
    }

    /**
     * Metodo utilizzato per estrapolare i ruoli dell'utente contenuti nell'header HTTP "SM_PRINCIPAL".
     * @return valore header HTTP "SM_PRINCIPAL"
     */
    public static String getSMPrincipal(HttpServletRequest request) {
        String sm_principal = request.getHeader(SM_PRINCIPAL);
        logger.debug("sm_principal: " + sm_principal);

        if (sm_principal == null || sm_principal.trim().length() == 0) {
            logger.warn("Roles not found");
        }

        return sm_principal;
    }

    /**
     * Metodo utilizzato per recuperare i profili dell'utente autenticato, laddove l'header HTTP "SM_PRINCIPAL" non venga valorizzata.
     * @param username nome utente autenticato.
     * @return lista dei ruoli appartenti all'utente autenticato.
     */
    public static List getRolesFromDb(String username) {
        List<String> list = new ArrayList<String>();
        try {
            DataSource ds = InitialContext.doLookup(SITEMINDER_DS);
            Connection conn = ds.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select Principal from dbo.fnQuerySchema_GetUserProperty('" + username + "')");
            if (rs != null) {
                while (rs.next()) {
                    list.add(rs.getString("Principal"));
                }
            }
        } catch (NamingException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return list;
    }

}
