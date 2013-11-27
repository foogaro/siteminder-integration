package it.redhat.inail.sm;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Valve utilizzato in EAP 6 per salvare per il thread della richiesta corrente la HttpServletRequest e poterla recuperare ed utilizzare in SMRedHatLoginModule.
 *
 * @author lfugaro@redhat.com
 */
public class RequestResponseHolder {

    private static ThreadLocal<Holder> holderThreadLocal = new ThreadLocal<Holder>();

    /**
     * Metodo utilizzato per impostare la HttpServletRequest e la HttpServletResponse.
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     */
    public static void setRequestAndResponse(HttpServletRequest request, HttpServletResponse response) {
        holderThreadLocal.set(new Holder(request, response));
    }

    /**
     * Metodo utilizzato per fare il reset della HttpServletRequest e della HttpServletResponse a fine richiesta.
     */
    public static void resetRequestAndResponse() {
        holderThreadLocal.set(null);
    }

    /**
     * Metodo utilizzato per il recupero della HttpServletRequest.
     * @return HttpServletRequest
     */
    public static HttpServletRequest getRequest() {
        Holder holder = holderThreadLocal.get();
        if (holder != null) {
            return holder.servletRequest;
        }

        return null;
    }

    /**
     * Metodo utilizzato per il recupero della HttpServletResponse.
     * @return HttpServletResponse
     */
    public static HttpServletResponse getResponse() {
        Holder holder = holderThreadLocal.get();
        if (holder != null) {
            return holder.servletResponse;
        }

        return null;
    }

    /**
     * Classe interna utilizzata come "contenitore" delle HttpServletRequest e HttpServletResponse.
     */
    private static class Holder {

        private final HttpServletRequest servletRequest;
        private final HttpServletResponse servletResponse;

        private Holder(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
            this.servletRequest = servletRequest;
            this.servletResponse = servletResponse;
        }
    }
}
