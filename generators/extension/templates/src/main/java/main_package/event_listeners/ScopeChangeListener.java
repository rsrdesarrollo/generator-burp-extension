package <%= package %>.event_listeners;

import burp.IScopeChangeListener;

public class ScopeChangeListener implements IScopeChangeListener {
    private static ScopeChangeListener mInstance;

    private ScopeChangeListener() {
    }

    public static ScopeChangeListener getInstance() {
        if (mInstance == null) {
            mInstance = new ScopeChangeListener();
        }
        return mInstance;
    }

    /**
     * This method is invoked whenever a change occurs to Burp's suite-wide
     * target scope.
     */
    @Override
    public void scopeChanged() {
    }
}
