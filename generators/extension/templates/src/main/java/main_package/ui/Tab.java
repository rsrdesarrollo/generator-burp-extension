package <%= package %>.ui;

import burp.ITab;
import <%= package %>.ui.forms.ExtensionTab;

import java.awt.*;

public class Tab implements ITab {
    private static Tab mInstance;

    private Tab() {
    }

    public static Tab getInstance() {
        if (mInstance == null) {
            mInstance = new Tab();
        }
        return mInstance;
    }

    @Override
    public String getTabCaption() {
        return "<%= name %>";
    }

    @Override
    public Component getUiComponent() {
        return ExtensionTab.getInstance().mainPanel;
    }
}
