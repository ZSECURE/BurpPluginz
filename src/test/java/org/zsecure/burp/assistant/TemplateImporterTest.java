package org.zsecure.burp.assistant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class TemplateImporterTest {
    @TempDir Path directory;

    @Test
    void importsOnlyAllowlistedFilesAndPreservesSourceAndMetadata() throws Exception {
        String source = "---\ncategory: WEB\ncvss: 7.0\n---\n# Test title\n\nText {==URL==}\n";
        byte[] bytes = source.getBytes(StandardCharsets.UTF_8);
        Files.write(directory.resolve("insufficient_cookie_protection.md"), bytes);
        Files.writeString(directory.resolve("other.md"), source);

        var result = new TemplateImporter().importDirectory(directory);

        assertEquals(62, TemplateImporter.IDS.size());
        assertEquals(1, result.templates().size());
        var template = result.templates().get(0);
        assertEquals("insufficient_cookie_protection", template.id());
        assertEquals("Test title", template.title());
        assertEquals("WEB", template.category());
        assertEquals("7.0", template.cvss());
        assertEquals(source, template.markdown());
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
                template.sha256());
        assertEquals(61, result.diagnostics().size());
    }

    @Test
    void rejectsUnsafeYamlDuplicateKeysOversizedAndInvalidUtf8() throws Exception {
        Files.writeString(directory.resolve("sql_injection.md"),
                "---\ncategory: !!java.net.URL [\"https://example.invalid\"]\ncvss: 5\n---\n# Test\n");
        Files.writeString(directory.resolve("open_url_redirection.md"),
                "---\ncategory: a\ncategory: b\ncvss: 5\n---\n# Test\n");
        Files.write(directory.resolve("insufficient_cookie_protection.md"),
                new byte[TemplateImporter.MAX_BYTES + 1]);
        Files.write(directory.resolve("passwords_stored_in_clear_text.md"), new byte[]{(byte) 0xff});

        var result = new TemplateImporter().importDirectory(directory);
        assertTrue(result.templates().isEmpty());
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.startsWith("sql_injection: could not import")));
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.startsWith("open_url_redirection: could not import")));
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.startsWith("insufficient_cookie_protection: could not import")));
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.startsWith("passwords_stored_in_clear_text: could not import")));
    }

    @Test
    void doesNotFollowSymbolicLinks() throws Exception {
        Path target = directory.resolve("outside.md");
        Files.writeString(target, "---\ncategory: WEB\ncvss: N/A\n---\n# Test\n");
        Files.createSymbolicLink(directory.resolve("sql_injection.md"), target);

        var result = new TemplateImporter().importDirectory(directory);
        assertTrue(result.templates().isEmpty());
        assertTrue(result.diagnostics().stream().anyMatch(s -> s.startsWith("sql_injection: missing")));
        assertThrows(java.io.IOException.class,
                () -> new TemplateImporter().importDirectory(directory.resolve("sql_injection.md")));
    }

    @Test
    void flagsUnresolvedOrMissingMetadata() throws Exception {
        Files.writeString(directory.resolve("sql_injection.md"),
                "---\ncategory: '{==CATEGORY==}'\n---\n# Test\n");
        var result = new TemplateImporter().importDirectory(directory);
        assertEquals(1, result.templates().size());
        assertTrue(result.diagnostics().contains("sql_injection: category requires review"));
        assertTrue(result.diagnostics().contains("sql_injection: CVSS requires review"));
    }
}
