package org.zsecure.burp.assistant;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.ui.UserInterface;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AssistantExtensionTest {
    @Test
    void registersOnlyTheSuiteTabAndDoesSoOnTheEventThread() {
        List<String> calls = new ArrayList<>();
        Extension extension = proxy(Extension.class, (method, arguments) -> {
            calls.add("extension." + method);
            assertEquals("Web Application Assistant", arguments[0]);
            return null;
        });
        UserInterface ui = proxy(UserInterface.class, (method, arguments) -> {
            calls.add("ui." + method);
            assertTrue(SwingUtilities.isEventDispatchThread());
            assertEquals("Web Assistant", arguments[0]);
            assertInstanceOf(TemplatePanel.class, arguments[1]);
            return null;
        });
        MontoyaApi api = proxy(MontoyaApi.class, (method, arguments) -> switch (method) {
            case "extension" -> extension;
            case "userInterface" -> ui;
            default -> throw new AssertionError("Unexpected API call: " + method);
        });

        new AssistantExtension().initialize(api);

        assertEquals(List.of("extension.setName", "ui.registerSuiteTab"), calls);
    }

    private interface Handler {
        Object invoke(String method, Object[] arguments);
    }

    private static <T> T proxy(Class<T> type, Handler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> handler.invoke(method.getName(), args)));
    }
}
