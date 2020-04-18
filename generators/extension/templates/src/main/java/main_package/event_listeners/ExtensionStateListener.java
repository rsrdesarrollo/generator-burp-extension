package <%= package %>.event_listeners;

import burp.IExtensionStateListener;

public class ExtensionStateListener implements IExtensionStateListener {

    private static ExtensionStateListener mInstance;

    private ExtensionStateListener() {
    }

    public static ExtensionStateListener getInstance() {
        if (mInstance == null) {
            mInstance = new ExtensionStateListener();
        }
        return mInstance;
    }

    /**
     * This method is called when the extension is unloaded.
     */
    @Override
    public void extensionUnloaded() {
        // TODO: Do something to clean out.
    }
}
