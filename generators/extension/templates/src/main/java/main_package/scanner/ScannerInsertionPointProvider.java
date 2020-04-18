package <%= package %>.scanner;

import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;

import java.util.ArrayList;
import java.util.List;

public class ScannerInsertionPointProvider implements IScannerInsertionPointProvider {


    private static ScannerInsertionPointProvider mInstance;

    private ScannerInsertionPointProvider() {
    }

    public static ScannerInsertionPointProvider getInstance() {
        if (mInstance == null) {
            mInstance = new ScannerInsertionPointProvider();
        }
        return mInstance;
    }

    /**
     * When a request is actively scanned, the Scanner will invoke this method,
     * and the provider should provide a list of custom insertion points that
     * will be used in the scan. <b>Note:</b> these insertion points are used in
     * addition to those that are derived from Burp Scanner's configuration, and
     * those provided by any other Burp extensions.
     *
     * @param baseRequestResponse The base request that will be actively
     *                            scanned.
     * @return A list of
     * <code>IScannerInsertionPoint</code> objects that should be used in the
     * scanning, or
     * <code>null</code> if no custom insertion points are applicable for this
     * request.
     */
    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        ArrayList<IScannerInsertionPoint> insertionPoints = new ArrayList<>();

        insertionPoints.add(new ScannerInsertionPoint());

        return insertionPoints;
    }

    private static class ScannerInsertionPoint implements IScannerInsertionPoint {

        /**
         * This method returns the name of the insertion point.
         *
         * @return The name of the insertion point (for example, a description of a
         * particular request parameter).
         */
        @Override
        public String getInsertionPointName() {
            // TODO:
            return null;
        }

        /**
         * This method returns the base value for this insertion point.
         *
         * @return the base value that appears in this insertion point in the base
         * request being scanned, or <code>null</code> if there is no value in the
         * base request that corresponds to this insertion point.
         */
        @Override
        public String getBaseValue() {
            // TODO:
            return null;
        }

        /**
         * This method is used to build a request with the specified payload placed
         * into the insertion point. There is no requirement for extension-provided
         * insertion points to adjust the Content-Length header in requests if the
         * body length has changed, although Burp-provided insertion points will
         * always do this and will return a request with a valid Content-Length
         * header.
         * <b>Note:</b>
         * Scan checks should submit raw non-encoded payloads to insertion points,
         * and the insertion point has responsibility for performing any data
         * encoding that is necessary given the nature and location of the insertion
         * point.
         *
         * @param payload The payload that should be placed into the insertion
         *                point.
         * @return The resulting request.
         */
        @Override
        public byte[] buildRequest(byte[] payload) {
            // TODO:
            return new byte[0];
        }

        /**
         * This method is used to determine the offsets of the payload value within
         * the request, when it is placed into the insertion point. Scan checks may
         * invoke this method when reporting issues, so as to highlight the relevant
         * part of the request within the UI.
         *
         * @param payload The payload that should be placed into the insertion
         *                point.
         * @return An int[2] array containing the start and end offsets of the
         * payload within the request, or null if this is not applicable (for
         * example, where the insertion point places a payload into a serialized
         * data structure, the raw payload may not literally appear anywhere within
         * the resulting request).
         */
        @Override
        public int[] getPayloadOffsets(byte[] payload) {
            // TODO:
            return new int[0];
        }

        /**
         * This method returns the type of the insertion point.
         *
         * @return The type of the insertion point. Available types are defined in
         * this interface.
         */
        @Override
        public byte getInsertionPointType() {
            // TODO: Define right type
            return IScannerInsertionPoint.INS_UNKNOWN;
        }
    }
}
