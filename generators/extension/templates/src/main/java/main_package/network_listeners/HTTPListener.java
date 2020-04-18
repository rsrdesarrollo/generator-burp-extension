package <%= package %>.network_listeners;

import burp.IHttpListener;
import burp.IHttpRequestResponse;

public class HTTPListener implements IHttpListener {


    private static HTTPListener mInstance;

    private HTTPListener() {
    }

    public static HTTPListener getInstance() {
        if (mInstance == null) {
            mInstance = new HTTPListener();
        }
        return mInstance;
    }

    /**
     * This method is invoked when an HTTP request is about to be issued, and
     * when an HTTP response has been received.
     *
     * @param toolFlag         A flag indicating the Burp tool that issued the request. Burp tool flags are defined in
     *                         the <code>IBurpExtenderCallbacks</code> interface.
     * @param messageIsRequest Flags whether the method is being invoked for a request or response.
     * @param messageInfo      Details of the request / response to be processed. Extensions can call the setter
     *                         methods on this object to update the current message and so modify Burp's behavior.
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // TODO
    }
}
