package org.zsecure.burp.assistant;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;

public final class AssistantExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Web Application Assistant");
        Runnable register = () -> api.userInterface().registerSuiteTab("Web Assistant", new TemplatePanel());
        if (SwingUtilities.isEventDispatchThread()) {
            register.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(register);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Extension initialization interrupted", e);
            } catch (InvocationTargetException e) {
                throw new IllegalStateException("Extension initialization failed", e.getCause());
            }
        }
    }
}
