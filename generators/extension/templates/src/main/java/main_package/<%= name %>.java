package <%- package -%>;

import burp.IBurpExtenderCallbacks;
<% if (classes.state_listener) { -%>
import <%- package -%>.event_listeners.ExtensionStateListener;
<% } -%>
<% if (classes.scanner_listener) { -%>
import <%- package -%>.event_listeners.ScannerListener;
<% } -%>
<% if (classes.scope_listener) { -%>
import <%- package -%>.event_listeners.ScopeChangeListener;
<% } -%>
<% if (classes.intruder_generator) { -%>
import <%- package -%>.intruder.IntruderPayloadGeneratorFactory;
<% } -%>
<% if (classes.intruder_processor) { -%>
import <%- package -%>.intruder.IntruderPayloadProcessor;
<% } -%>
<% if (classes.http_listener) { -%>
import <%- package -%>.network_listeners.HTTPListener;
<% } -%>
<% if (classes.proxy_listener) { -%>
import <%- package -%>.network_listeners.ProxyListener;
<% } -%>
<% if (classes.scanner_chack) { -%>
import <%- package -%>.scanner.ScannerCheck;
<% } -%>
<% if (classes.scanner_insert_point) { -%>
import <%- package -%>.scanner.ScannerInsertionPointProvider;
<% } -%>
<% if (classes.session) { -%>
import <%- package -%>.session.SessionHandlingAction;
<% } -%>
<% if (classes.menu) { -%>
import <%- package -%>.ui.ContextMenu;
<% } -%>
<% if (classes.editor) { -%>
import <%- package -%>.ui.MessageEditorTabFactory;
<% } -%>
<% if (classes.tab) { -%>
import <%- package -%>.ui.Tab;
<% } -%>

public class <%- name -%> {

    private static <%- name -%> mInstance;
    private IBurpExtenderCallbacks callbacks;

    private <%- name -%>() {
    }

    public static <%- name -%> getInstance() {
        if (mInstance == null) {
            mInstance = new <%- name -%>();
        }
        return mInstance;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public void setCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public void init() {
<% if (classes.tab) { -%>
        this.callbacks.addSuiteTab(Tab.getInstance());
<% } -%>
<% if (classes.proxy_listener) { -%>
        this.callbacks.registerProxyListener(ProxyListener.getInstance());
<% } -%>
<% if (classes.http_listener) { -%>
        this.callbacks.registerHttpListener(HTTPListener.getInstance());
<% } -%>
<% if (classes.menu) { -%>
        this.callbacks.registerContextMenuFactory(ContextMenu.getInstance());
<% } -%>
<% if (classes.state_listener) { -%>
        this.callbacks.registerExtensionStateListener(ExtensionStateListener.getInstance());
<% } -%>
<% if (classes.scanner_listener) { -%>
        this.callbacks.registerScannerListener(ScannerListener.getInstance());
<% } -%>
<% if (classes.intruder_generator) { -%>
        this.callbacks.registerIntruderPayloadGeneratorFactory(IntruderPayloadGeneratorFactory.getInstance());
<% } -%>
<% if (classes.editor) { -%>
        this.callbacks.removeMessageEditorTabFactory(MessageEditorTabFactory.getInstance());
<% } -%>
<% if (classes.scanner_insert_point) { -%>
        this.callbacks.registerScannerInsertionPointProvider(ScannerInsertionPointProvider.getInstance());
<% } -%>
<% if (classes.session) { -%>
        this.callbacks.registerSessionHandlingAction(SessionHandlingAction.getInstance());
<% } -%>
<% if (classes.intruder_processor) { -%>
        this.callbacks.registerIntruderPayloadProcessor(IntruderPayloadProcessor.getInstance());
<% } -%>
<% if (classes.scanner_chack) { -%>
        this.callbacks.registerScannerCheck(ScannerCheck.getInstance());
<% } -%>
<% if (classes.scope_listener) { -%>
        this.callbacks.registerScopeChangeListener(ScopeChangeListener.getInstance());
<% } -%>
    }

}
