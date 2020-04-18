package <%= package %>.intruder;

import burp.IIntruderPayloadProcessor;

public class IntruderPayloadProcessor implements IIntruderPayloadProcessor {
    private static final String PROCESSOR_NAME = "Custom Processor Name"; // TODO: Change processor name
    private static IntruderPayloadProcessor mInstance;

    private IntruderPayloadProcessor() {
    }

    public static IntruderPayloadProcessor getInstance() {
        if (mInstance == null) {
            mInstance = new IntruderPayloadProcessor();
        }
        return mInstance;
    }


    /**
     * This method is used by Burp to obtain the name of the payload processor.
     * This will be displayed as an option within the Intruder UI when the user
     * selects to use an extension-provided payload processor.
     *
     * @return The name of the payload processor.
     */
    @Override
    public String getProcessorName() {
        return PROCESSOR_NAME;
    }

    /**
     * This method is invoked by Burp each time the processor should be applied
     * to an Intruder payload.
     *
     * @param currentPayload  The value of the payload to be processed.
     * @param originalPayload The value of the original payload prior to
     *                        processing by any already-applied processing rules.
     * @param baseValue       The base value of the payload position, which will be
     *                        replaced with the current payload.
     * @return The value of the processed payload. This may be
     * <code>null</code> to indicate that the current payload should be skipped,
     * and the attack will move directly to the next payload.
     */
    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        // TODO:
        return new byte[0];
    }
}
