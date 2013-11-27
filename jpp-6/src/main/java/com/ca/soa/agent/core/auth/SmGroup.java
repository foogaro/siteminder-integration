package com.ca.soa.agent.core.auth;

import java.security.Principal;

/**
 * Questa classe sostituisce quella di CA (com.ca.soa.agent.core.auth.SmGroup in "asaagent-jboss.jar"), per garantire la retro compatibilita' con la libreria "SSOUtilsClientWebJBOSS.jar".
 *
 * @author lfugaro@redhat.com
 */
public class SmGroup implements Principal {

    private String name;

    /**
     * Returns the name of this principal.
     *
     * @return the name of this principal.
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * Sets the name of this principal.
     * @param name of this principal.
     */
    public void setName(String name) {
        this.name = name;
    }
}
