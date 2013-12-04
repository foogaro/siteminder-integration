package org.jboss.security.plugins;

import com.ca.soa.agent.core.auth.SmGroup;
import it.redhat.inail.sm.SSOUtils;
import org.jboss.logging.Logger;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Questa classe sostituisce quella di JBoss EAP 5, per garantire la retro compatibilita' con la libreria "SSOUtilsClientWebJBOSS.jar".
 * @author lfugaro@redhat.com
 */
public class JaasSecurityManager {

    private static Logger logger = Logger.getLogger(SSOUtils.class);

    public Set getUserRoles(Principal principal) {

        logger.debug("Getting Roles for Principal: " + principal);
        Subject caller = null;
        try {
            caller = SSOUtils.getSubject();
            if(caller!=null) {
                List<String> roles = SSOUtils.getRolesFromDb(principal.getName());
                logger.debug("roles: " + roles);
                Set set = new HashSet();
                for (String role : roles) {
                    logger.debug("role: " + role);
                    SmGroup smGroup = new SmGroup();
                    smGroup.setName(role);
                    set.add(smGroup);
                }
                return set;

//                return caller.getPrincipals();
/*
                Set<Principal> principals = caller.getPrincipals();
                Set set = new HashSet();
                for (Principal principal1 : principals) {
                    SmGroup smGroup = new SmGroup();
                    smGroup.setName(principal.getName());
                    set.add(smGroup);
                }
                return set;
*/
            } else {
                logger.warn("SecurityContext not found");
            }
        } catch (Throwable t) {
            logger.error("Errore: {}", t);
        }
        return new HashSet();
    }
}
