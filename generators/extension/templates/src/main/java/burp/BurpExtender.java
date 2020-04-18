package burp;

import <%= package %>.<%= name %>;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        <%= name %> mainInstance = <%= name %>.getInstance();
        mainInstance.setCallbacks(callbacks);

        mainInstance.init();
    }

    public static void main (String [ ] args) {
        System.out.println("You have built this extension. You shall play with the jar file now!");
    }
}
