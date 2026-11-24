package org.zsecure.burp.assistant;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class TemplateImporter {
    static final int MAX_BYTES = 256 * 1024;
    static final Set<String> IDS = Set.of(
            "arbitrary_text_injection", "captcha_images_fairly_weak",
            "changing_password_does_not_require_current_password", "cookies_scoped_to_parent_domain",
            "credentials_in_clear_text_in_source_code", "cross-site_request_forgery",
            "csv_formula_injection", "default_installation_files_on_website",
            "development_placeholder_text_present", "dynamic_cross_origin_resource_sharing_policy",
            "emails_html_url_injection", "functionality_insufficiently_protected_from_automated_attacks",
            "graphql_allows_introspection_query", "hardcoded_encryption_keys", "image_only_captcha_in_use",
            "insecure_development_practices", "insufficient_access_control", "insufficient_cookie_protection",
            "insufficient_expiry_time_for_password_reset_token", "insufficient_input_validation_and_sanitisation",
            "internal_ip_addresses_in_source_code", "login_uses_existing_session",
            "logout_does_not_clear_server_session", "no_account_lockout_or_password_complexity",
            "no_account_verification_mechanism", "no_logout_functionality", "no_password_change_functionality",
            "old_version_of_javascript_libraries", "old_versions_of_wordpress_and_plugins", "open_url_redirection",
            "overly_permissive_content_security_policy", "passwords_emailed_in_clear_text",
            "passwords_stored_as_md5_hashes", "passwords_stored_in_clear_text",
            "potentially_insufficient_logging_and_monitoring", "reflected_cross-site_scripting",
            "secure_content_caching_permitted", "send_to_friend_spam_abuse", "sensitive_data_in_local_storage",
            "sensitive_information_in_http_get_request", "server-side_request_forgery",
            "session_cookie_has_long_expiry_time", "session_id_in_website_urls", "sql_injection",
            "stored_cross-site_scripting", "test_and_backup_pages_on_website", "unrestricted_file_upload",
            "uploaded_files_not_scanned_for_malware", "usernames_stored_in_cookies",
            "version_of_software_in_source_code", "weak_authentication_mechanism",
            "website_admin_allows_script_file_upload", "website_functionality_provided_by_cross-domain_includes",
            "website_not_cross_browser_compatible", "website_pages_allow_username_harvesting",
            "website_pages_load_mixed_content", "website_processes_cardholder_data",
            "website_relies_on_asp.net_request_validation", "website_supports_concurrent_sessions",
            "website_uses_predictable_ids", "wordpress_debug_logs_publicly_accessible",
            "xml_external_entity_injection");

    record Template(String id, String title, String category, String cvss, String markdown, String sha256) {
        @Override public String toString() { return title + " (" + id + ")"; }
    }

    record Result(List<Template> templates, List<String> diagnostics) { }

    Result importDirectory(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Select a directory (not a symbolic link).");
        }
        List<Template> templates = new ArrayList<>();
        List<String> diagnostics = new ArrayList<>();
        for (String id : IDS.stream().sorted().toList()) {
            Path file = directory.resolve(id + ".md");
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                diagnostics.add(id + ": missing or not a regular file");
                continue;
            }
            try (InputStream input = Files.newInputStream(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                byte[] bytes = input.readNBytes(MAX_BYTES + 1);
                if (bytes.length > MAX_BYTES) {
                    throw new IllegalArgumentException("file exceeds size limit");
                }
                Template template = parse(id, bytes);
                templates.add(template);
                if (unresolved(template.category()) || template.category().equalsIgnoreCase("N/A")) {
                    diagnostics.add(id + ": category requires review");
                }
                if (unresolved(template.cvss())) {
                    diagnostics.add(id + ": CVSS requires review");
                }
            } catch (IOException | RuntimeException e) {
                diagnostics.add(id + ": could not import (invalid, unsafe, or unreadable file)");
            }
        }
        return new Result(List.copyOf(templates), List.copyOf(diagnostics));
    }

    private boolean unresolved(String value) {
        return value.isBlank() || value.contains("{") || value.equalsIgnoreCase("TBC");
    }

    private Template parse(String id, byte[] bytes) throws IOException {
        String text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        String[] parts = text.split("(?m)^---\\s*$", 3);
        if (parts.length != 3 || !parts[0].isBlank()) {
            throw new IllegalArgumentException("missing front matter");
        }
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setNestingDepthLimit(20);
        options.setCodePointLimit(MAX_BYTES);
        Yaml yaml = new Yaml(new SafeConstructor(options));
        Object loaded = yaml.load(parts[1]);
        if (!(loaded instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("front matter must be a mapping");
        }
        var root = yaml.compose(new java.io.StringReader(parts[1]));
        if (!(root instanceof MappingNode mapping)) {
            throw new IllegalArgumentException("front matter must be a mapping");
        }
        String category = scalar(mapping, "category");
        String cvss = scalar(mapping, "cvss");
        String title = parts[2].lines()
                .filter(line -> line.startsWith("# "))
                .map(line -> line.substring(2).trim())
                .filter(line -> !line.isEmpty())
                .findFirst().orElse(id);
        try {
            return new Template(id, title, category, cvss, text,
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String scalar(MappingNode mapping, String name) {
        for (NodeTuple entry : mapping.getValue()) {
            if (entry.getKeyNode() instanceof ScalarNode key && name.equals(key.getValue())) {
                if (entry.getValueNode() instanceof ScalarNode value) {
                    return value.getValue();
                }
                throw new IllegalArgumentException("metadata must be scalar");
            }
        }
        return "";
    }
}
