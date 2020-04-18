package <%= package %>.session;

import burp.IHttpRequestResponse;
import burp.ISessionHandlingAction;

public class SessionHandlingAction implements ISessionHandlingAction {
    private static final String ACTION_NAME = "My Session Action";  // TODO: Set session action name
    private static SessionHandlingAction mInstance;

    private SessionHandlingAction() {
    }

    public static SessionHandlingAction getInstance() {
        if (mInstance == null) {
            mInstance = new SessionHandlingAction();
        }
        return mInstance;
    }


    /**
     * This method is used by Burp to obtain the name of the session handling
     * action. This will be displayed as an option within the session handling
     * rule editor when the user selects to execute an extension-provided
     * action.
     *
     * @return The name of the action.
     */
    @Override
    public String getActionName() {
        return ACTION_NAME;
    }

    /**
     * This method is invoked when the session handling action should be
     * executed. This may happen as an action in its own right, or as a
     * sub-action following execution of a macro.
     *
     * @param currentRequest The base request that is currently being processed.
     *                       The action can query this object to obtain details about the base
     *                       request. It can issue additional requests of its own if necessary, and
     *                       can use the setter methods on this object to update the base request.
     * @param macroItems     If the action is invoked following execution of a
     *                       macro, this parameter contains the result of executing the macro.
     *                       Otherwise, it is
     *                       <code>null</code>. Actions can use the details of the macro items to
     *                       perform custom analysis of the macro to derive values of non-standard
     *                       session handling tokens, etc.
     */
    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        // TODO
    }
}
