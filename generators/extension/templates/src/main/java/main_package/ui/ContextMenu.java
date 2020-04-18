package <%= package %>.ui;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenu implements IContextMenuFactory {

    private static ContextMenu mInstance;

    private ContextMenu() {
    }

    public static ContextMenu getInstance() {
        if (mInstance == null) {
            mInstance = new ContextMenu();
        }
        return mInstance;
    }

    /**
     * This method will be called by Burp when the user invokes a context menu
     * anywhere within Burp. The factory can then provide any custom context
     * menu items that should be displayed in the context menu, based on the
     * details of the menu invocation.
     *
     * @param invocation An object that implements the
     *                   <code>IMessageEditorTabFactory</code> interface, which the extension can
     *                   query to obtain details of the context menu invocation.
     * @return A list of custom menu items (which may include sub-menus,
     * checkbox menu items, etc.) that should be displayed. Extensions may
     * return
     * <code>null</code> from this method, to indicate that no menu items are
     * required.
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> items = new ArrayList<>();

        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS:
            case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
            case IContextMenuInvocation.CONTEXT_SCANNER_RESULTS:
            case IContextMenuInvocation.CONTEXT_SEARCH_RESULTS:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:

                JMenuItem action1 = new JMenuItem("Sample Action");
                action1.addActionListener(e -> {
                    // TODO: Do Something probably with invocation variable.
                });

                break;
        }

        return items;
    }
}
