package it.redhat.inail.sm.login;

import it.redhat.inail.sm.SSOUtils;
import it.redhat.inail.sm.model.SiteMinderUserRoles;
import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.component.ComponentRequestLifecycle;
import org.exoplatform.container.component.RequestLifeCycle;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.organization.Group;
import org.exoplatform.services.organization.MembershipType;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.idm.ExtGroup;
import org.exoplatform.services.organization.idm.UserImpl;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.services.security.jaas.AbstractLoginModule;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import static it.redhat.inail.sm.Const.SITEMINDER_DS;

/**
 * @author lfugaro@redhat.com
 */
public class SMRedHatPortalLoginModule extends AbstractLoginModule {

    private static final Log log = ExoLogger.getLogger(SMRedHatPortalLoginModule.class);

    /** JACC get context method. */
    private static Method getContextMethod;

    static {
        try {
            Class<?> policyContextClass = Thread.currentThread().getContextClassLoader().loadClass("javax.security.jacc.PolicyContext");
            getContextMethod = policyContextClass.getDeclaredMethod("getContext", String.class);
        } catch (ClassNotFoundException ignore) {
            log.debug("JACC not found ignoring it", ignore);
        } catch (Exception e) {
            log.error("Could not obtain JACC get context method", e);
        }
    }


    @Override
    protected Log getLogger() {
        return log;
    }


    @Override
    public boolean login() throws LoginException {
        try {
            ExoContainer container = getContainer();

            HttpServletRequest servletRequest = getCurrentHttpServletRequest();
            if (servletRequest == null) {
                log.debug("HttpServletRequest is null. SMRedHatPortalLoginModule will be ignored.");
                return false;
            }

            String username = SSOUtils.getSMUser(servletRequest);
            log.debug("username: " + username);
            if (username == null || "".equals(username.trim())) {
                log.debug("SiteMinder user not found");
                return false;
            } else {
                log.debug("SiteMinder user found");
                addUserToPlatformUsers(username);
            }
            establishSecurityContext(container, username);

            if (log.isTraceEnabled()) {
                log.trace("Successfully established security context for user " + username);
            }
            return true;
        } catch (Exception e) {
            if (log.isTraceEnabled()) {
                log.trace("Exception in login module", e);
            }
            throw new LoginException("OAuth login failed due to exception: " + e.getClass() + ": " + e.getMessage());
        }
    }


    @Override
    public boolean commit() throws LoginException {
        return true;
    }


    @Override
    public boolean abort() throws LoginException {
        return true;
    }


    @Override
    public boolean logout() throws LoginException {
        return true;
    }




    protected void establishSecurityContext(ExoContainer container, String username) throws Exception {
        Authenticator authenticator = (Authenticator) container.getComponentInstanceOfType(Authenticator.class);

        if (authenticator == null) {
            throw new LoginException("No Authenticator component found, check your configuration");
        }

        Identity identity = authenticator.createIdentity(username);

        sharedState.put("exo.security.identity", identity);
        sharedState.put("javax.security.auth.login.name", username);
        subject.getPublicCredentials().add(new UsernameCredential(username));
    }

    // Forked from SSOLoginModule
    protected HttpServletRequest getCurrentHttpServletRequest() {
        HttpServletRequest request = null;

        // JBoss way
        if (getContextMethod != null) {
            try {
                request = (HttpServletRequest)getContextMethod.invoke(null, "javax.servlet.http.HttpServletRequest");
            } catch(Throwable e) {
                log.error("LoginModule error. Turn off session credentials checking with proper configuration option of " +
                        "LoginModule set to false");
                log.error(this, e);
            }
        } else {
            // Tomcat way (Assumed that ServletAccessValve has been configured in context.xml)
            try {
                // TODO: improve this
                Class<?> clazz = Thread.currentThread().getContextClassLoader().loadClass("org.gatein.sso.agent.tomcat.ServletAccess");
                Method getRequestMethod = clazz.getDeclaredMethod("getRequest");
                request = (HttpServletRequest)getRequestMethod.invoke(null);
            } catch (Exception e) {
                log.error("Unexpected exception when trying to obtain HttpServletRequest from ServletAccess thread-local", e);
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("Returning HttpServletRequest " + request);
        }

        return request;
    }

    private void addUserToPlatformUsers(String userId) throws Exception {
        OrganizationService orgService = (OrganizationService) getContainer().getComponentInstanceOfType(OrganizationService.class);
        String membershipType = "member";
        String groupId = "/platform/users";
        try {
            begin(orgService);

            MembershipType memberType = orgService.getMembershipTypeHandler().findMembershipType(membershipType);

            User user = orgService.getUserHandler().findUserByName(userId);
            log.debug("user: " + user);
            if (user == null) {
                log.debug("Adding the new portal user");
                SiteMinderUserRoles siteMinderUserRoles = createUser(userId);
                user = siteMinderUserRoles.getUser();
                log.debug("user: " + user);
                orgService.getUserHandler().createUser(user, Boolean.TRUE); //TODO: capire le implicazioni del TRUE (broadcast);
                user = orgService.getUserHandler().findUserByName(userId);
                log.debug("user-created: " + user);

                for (Group group : siteMinderUserRoles.getGroups()) {
                    log.debug("group: " + group);
                    Group current = orgService.getGroupHandler().findGroupById(group.getGroupName());
                    log.debug("current: " + current);
                    if (current == null)  {
                        log.debug("Adding the new group");
                        orgService.getGroupHandler().createGroup(group, Boolean.TRUE);
                        orgService.getMembershipHandler().linkMembership(user, group, memberType, true);
                    }
                }
            }

            log.debug("Adding the standard /platform/users membership");
            // Standard /platform/users membership
            Group platformUsersGroup = orgService.getGroupHandler().findGroupById(groupId);
            orgService.getMembershipHandler().linkMembership(user, platformUsersGroup, memberType, true);
        } catch (Exception e) {
            log.error("Failed to add user " + userId + " to group " + groupId + ".", e);
            // don't rethrow login exception in case of failure.
            // throw e;
        } finally {
            end(orgService);
        }
    }

    private SiteMinderUserRoles createUser(String userId) {
        User user = new UserImpl(userId);
        List<Group> groups = new ArrayList<Group>();

        //TODO: impostare i valori che provengono dal policy server
        //TODO: implementare un meccanismo di cache e di eviction tale per cui questi valori siano "revocati" coerentemente con quanto definito nel PolicyServer.
        try {
            DataSource ds = InitialContext.doLookup(SITEMINDER_DS);
            Connection conn = ds.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select * from dbo.fnQuerySchema_GetUserProperty('" + userId + "')");
            if (rs != null) {
                while (rs.next()) {
                    user.setDisplayName(rs.getString("nomecognome"));
                    user.setEmail(rs.getString("email"));
                    user.setFirstName(rs.getString("nome"));
                    user.setLastName(rs.getString("cognome"));
                    Group group = new ExtGroup();
                    group.setLabel(rs.getString("Principal"));group.setGroupName(group.getLabel());
                    groups.add(group);
                }
                user.setOrganizationId("INAIL");
                user.setPassword("Inail.2013");
            }
        } catch (NamingException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return new SiteMinderUserRoles(user, groups);
    }

    private void begin(OrganizationService orgService) {
        if (orgService instanceof ComponentRequestLifecycle) {
            RequestLifeCycle.begin((ComponentRequestLifecycle) orgService);
        }
    }

    private void end(OrganizationService orgService) {
        if (orgService instanceof ComponentRequestLifecycle) {
            RequestLifeCycle.end();
        }
    }

}
