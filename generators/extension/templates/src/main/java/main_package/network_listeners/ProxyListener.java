package <%= package %>.network_listeners;

import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

public class ProxyListener implements IProxyListener {


    private static ProxyListener mInstance;

    private ProxyListener() {
    }

    public static ProxyListener getInstance() {
        if (mInstance == null) {
            mInstance = new ProxyListener();
        }
        return mInstance;
    }

    /**
     * This method is invoked when an HTTP message is being processed by the
     * Proxy.
     *
     * @param messageIsRequest Indicates whether the HTTP message is a request or a response.
     * @param message          An <code>IInterceptedProxyMessage</code> object that extensions can use to
     *                         query and update details of the message, and control whether the message
     *                         should be intercepted and displayed to the user for manual review or
     *                         modification.
     */
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // TODO
    }
}
