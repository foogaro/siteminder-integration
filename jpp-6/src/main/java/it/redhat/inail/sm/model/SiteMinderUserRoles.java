package it.redhat.inail.sm.model;

import org.exoplatform.services.organization.Group;
import org.exoplatform.services.organization.User;

import java.util.List;

/**
 * @author lfugaro@redhat.com
 */
public class SiteMinderUserRoles {

    private User user = null;
    private List<Group> groups = null;

    public SiteMinderUserRoles(User user, List<Group> groups) {
        this.user = user;
        this.groups = groups;
    }

    public User getUser() {
        return user;
    }

    public List<Group> getGroups() {
        return groups;
    }


}
