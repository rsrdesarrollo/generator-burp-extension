package <%= package %>.intruder;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

public class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {
    private static final String GENERATOR_NAME = "Custom Generator Name"; // TODO: change generator name
    private static IntruderPayloadGeneratorFactory mInstance;

    private IntruderPayloadGeneratorFactory() {
    }

    public static IntruderPayloadGeneratorFactory getInstance() {
        if (mInstance == null) {
            mInstance = new IntruderPayloadGeneratorFactory();
        }
        return mInstance;
    }

    /**
     * This method is used by Burp to obtain the name of the payload generator.
     * This will be displayed as an option within the Intruder UI when the user
     * selects to use extension-generated payloads.
     *
     * @return The name of the payload generator.
     */
    @Override
    public String getGeneratorName() {
        return GENERATOR_NAME;
    }

    /**
     * This method is used by Burp when the user starts an Intruder attack that
     * uses this payload generator.
     *
     * @param attack An <code>IIntruderAttack</code> object that can be queried to
     *               obtain details about the attack in which the payload generator
     *               will be used.
     * @return A new instance of
     * <code>IIntruderPayloadGenerator</code> that will be used to generate
     * payloads for the attack.
     */
    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new IntruderPayloadGenerator(attack);
    }

    private static class IntruderPayloadGenerator implements IIntruderPayloadGenerator {
        private final IIntruderAttack attack;

        public IntruderPayloadGenerator(IIntruderAttack attack) {
            this.attack = attack;
        }

        /**
         * This method is used by Burp to determine whether the payload generator is
         * able to provide any further payloads.
         *
         * @return Extensions should return
         * <code>false</code> when all the available payloads have been used up,
         * otherwise
         * <code>true</code>.
         */
        @Override
        public boolean hasMorePayloads() {
            return false;
        }

        /**
         * This method is used by Burp to obtain the value of the next payload.
         *
         * @param baseValue The base value of the current payload position. This
         *                  value may be <code>null</code> if the concept of a base
         *                  value is not applicable (e.g. in a battering ram attack).
         * @return The next payload to use in the attack.
         */
        @Override
        public byte[] getNextPayload(byte[] baseValue) {
            return new byte[0];
        }

        /**
         * This method is used by Burp to reset the state of the payload generator
         * so that the next call to
         * <code>getNextPayload()</code> returns the first payload again. This
         * method will be invoked when an attack uses the same payload generator for
         * more than one payload position, for example in a sniper attack.
         */
        @Override
        public void reset() {

        }
    }
}
