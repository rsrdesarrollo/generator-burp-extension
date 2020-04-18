package <%= package %>.event_listeners;

import burp.IScanIssue;
import burp.IScannerListener;

public class ScannerListener implements IScannerListener {


    private static ScannerListener mInstance;

    private ScannerListener() {
    }

    public static ScannerListener getInstance() {
        if (mInstance == null) {
            mInstance = new ScannerListener();
        }
        return mInstance;
    }

    /**
     * This method is invoked when a new issue is added to Burp Scanner's
     * results.
     *
     * @param issue An
     *              <code>IScanIssue</code> object that the extension can query to obtain
     *              details about the new issue.
     */
    @Override
    public void newScanIssue(IScanIssue issue) {

    }
}
