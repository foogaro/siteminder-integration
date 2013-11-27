package it.redhat.inail.sm.login;

import it.redhat.inail.sm.RequestResponseHolder;
import it.redhat.inail.sm.SSOUtils;
import org.jboss.logging.Logger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.IdentityLoginModule;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.security.acl.Group;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * @author lfugaro@redhat.com
 */
public class SMRedHatLoginModule extends IdentityLoginModule {

    private Logger logger = Logger.getLogger(getClass().getName());

    @Override
    public void initialize(Subject subject, CallbackHandler handler, Map<String, ?> sharedState, Map<String, ?> options) {
        Map<String, Object> map = new HashMap<String, Object>();
        Set<String> keys = options.keySet();
        for (String key : keys) {
            map.put(key, options.get(key));
        }
        map.put("principal", SSOUtils.getSMUser());
        super.initialize(subject, handler, sharedState, map);
    }

    @Override
    public boolean login() throws LoginException {
        return super.login();
    }

    @Override
    protected Principal getIdentity() {
        return super.getIdentity();
    }

    /**
     * Method to commit the authentication process (phase 2). If the login
     * method completed successfully as indicated by loginOk == true, this
     * method adds the getIdentity() value to the subject getPrincipals() Set.
     * It also adds the members of each Group returned by getRoleSets()
     * to the subject getPrincipals() Set.
     *
     * @return true always.
     * @see javax.security.auth.Subject;
     * @see java.security.acl.Group;
     */
    @Override
    public boolean commit() throws LoginException {
        return super.commit();
    }

    /**
     * Utility method to create a Principal for the given username. This
     * creates an instance of the principalClassName type if this option was
     * specified using the class constructor matching: ctor(String). If
     * principalClassName was not specified, a SimplePrincipal is created.
     *
     * @param username the name of the principal
     * @return the principal instance
     * @throws Exception thrown if the custom principal type cannot be created.
     */
    @Override
    protected Principal createIdentity(String username) throws Exception {
        return super.createIdentity(username);
    }

    @Override
    protected Group[] getRoleSets() throws LoginException {

        HttpServletRequest request = RequestResponseHolder.getRequest();

        SimpleGroup roles = new SimpleGroup("Roles");
        logger.debug("roles: " + roles);
        Group[] roleSets = {roles};
        try {
            String smPrincipal = SSOUtils.getSMPrincipal();
            logger.debug("smPrincipal: " + smPrincipal);
            if (smPrincipal != null && !"".equals(smPrincipal.trim())) {
                StringTokenizer tokenizer = new StringTokenizer(smPrincipal, "^", false);
                logger.debug("tokenizer: " + tokenizer);
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    logger.debug("token: " + token);
                    roles.addMember(new SimplePrincipal(token));
                }
            } else {
                throw new LoginException("Failed to create group member. No role at all.");
            }
            logger.debug("roleSets: " + roleSets);
        } catch (Exception e) {
            e.printStackTrace();
            throw new LoginException("Failed to create group member for " + roles);
        }

        logger.debug("returning roleSets");
        return roleSets;
    }

}