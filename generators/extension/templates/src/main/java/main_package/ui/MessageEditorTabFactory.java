package <%= package %>.ui;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import <%= package %>.ui.forms.EditorForm;

import java.awt.*;

public class MessageEditorTabFactory implements IMessageEditorTabFactory {
    private static MessageEditorTabFactory mInstance;

    private MessageEditorTabFactory() {
    }

    public static MessageEditorTabFactory getInstance() {
        if (mInstance == null) {
            mInstance = new MessageEditorTabFactory();
        }
        return mInstance;
    }

    /**
     * Burp will call this method once for each HTTP message editor, and the
     * factory should provide a new instance of an
     * <code>IMessageEditorTab</code> object.
     *
     * @param controller An <code>IMessageEditorController</code> object, which the new tab can query
     *                   to retrieve details about the currently displayed message. This may be
     *                   <code>null</code> for extension-invoked message editors where the
     *                   extension has not provided an editor controller.
     * @param editable   Indicates whether the hosting editor is editable or
     *                   read-only.
     * @return A new <code>IMessageEditorTab</code> object for use within the message editor.
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // TODO
        if (controller != null) {
            // TODO: Make decisions
        }

        return new MessageEditorTab();
    }

    private static class MessageEditorTab implements IMessageEditorTab {
        private static final String TAB_CAPTION = "My Editor"; // TODO: Set caption name

        /**
         * This method returns the caption that should appear on the custom tab when
         * it is displayed. <b>Note:</b> Burp invokes this method once when the tab
         * is first generated, and the same caption will be used every time the tab
         * is displayed.
         *
         * @return The caption that should appear on the custom tab when it is
         * displayed.
         */
        @Override
        public String getTabCaption() {
            return TAB_CAPTION;
        }

        /**
         * This method returns the component that should be used as the contents of
         * the custom tab when it is displayed. <b>Note:</b> Burp invokes this
         * method once when the tab is first generated, and the same component will
         * be used every time the tab is displayed.
         *
         * @return The component that should be used as the contents of the custom
         * tab when it is displayed.
         */
        @Override
        public Component getUiComponent() {
            return new EditorForm().mainPanel;
        }

        /**
         * The hosting editor will invoke this method before it displays a new HTTP
         * message, so that the custom tab can indicate whether it should be enabled
         * for that message.
         *
         * @param content   The message that is about to be displayed, or a zero-length
         *                  array if the existing message is to be cleared.
         * @param isRequest Indicates whether the message is a request or a
         *                  response.
         * @return The method should return
         * <code>true</code> if the custom tab is able to handle the specified
         * message, and so will be displayed within the editor. Otherwise, the tab
         * will be hidden while this message is displayed.
         */
        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // TODO
            return false;
        }

        /**
         * The hosting editor will invoke this method to display a new message or to
         * clear the existing message. This method will only be called with a new
         * message if the tab has already returned
         * <code>true</code> to a call to
         * <code>isEnabled()</code> with the same message details.
         *
         * @param content   The message that is to be displayed, or
         *                  <code>null</code> if the tab should clear its contents and disable any
         *                  editable controls.
         * @param isRequest Indicates whether the message is a request or a
         *                  response.
         */
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            // TODO
        }

        /**
         * This method returns the currently displayed message.
         *
         * @return The currently displayed message.
         */
        @Override
        public byte[] getMessage() {
            // TODO
            return new byte[0];
        }

        /**
         * This method is used to determine whether the currently displayed message
         * has been modified by the user. The hosting editor will always call
         * <code>getMessage()</code> before calling this method, so any pending
         * edits should be completed within
         * <code>getMessage()</code>.
         *
         * @return The method should return
         * <code>true</code> if the user has modified the current message since it
         * was first displayed.
         */
        @Override
        public boolean isModified() {
            // TODO
            return false;
        }

        /**
         * This method is used to retrieve the data that is currently selected by
         * the user.
         *
         * @return The data that is currently selected by the user. This may be
         * <code>null</code> if no selection is currently made.
         */
        @Override
        public byte[] getSelectedData() {
            // TODO
            return new byte[0];
        }
    }
}
