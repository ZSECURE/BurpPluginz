# Burp Web Application Assistant

This repository contains an **initial template-import prototype**, not the
complete product described in the PRD. It is not ready for engagement reporting.
The source issue bank is not included; use it only with the owner's permission.

## Build and load

With JDK 17 installed, run `./gradlew clean build`. The extension JAR is
`build/libs/burp-web-application-assistant.jar`. In Burp, load it as a Java
extension and select `org.zsecure.burp.assistant.AssistantExtension` if prompted.
The intended target is Burp Suite Professional v2026.11.2. The build targets
Montoya API 2026.7; loading and compatibility have not been verified in Burp.
Verify this in that version before use.

In the **Web Assistant** tab, choose the extracted `08_web_application`
directory. The importer reads only the 62 exact filenames in the PRD, with a
256 KiB per-file limit. It does not follow symbolic links, change source files,
or extract archives. The count and diagnostics show missing, unsafe, malformed,
or unresolved entries. Search covers IDs, titles, metadata, and raw content.
The raw preview is plain text and may include internal consultant guidance.
Templates are held in memory only and are not written to logs or persisted.

## Limitations and next steps

- ZIP import, rendered previews, findings, checklist, evidence management,
  passive observation, annotation, persistence, manual review, and export are
  **not implemented**. Scanner integration and active validation are also absent.
- No HTTP handlers or request generators are registered. No vulnerability
  detection or coverage assessment is performed.
- One user-provided issue example was validated for its quoted YAML metadata,
  third-level title, placeholders, and source preservation. The complete
  proprietary archive and all 62 imports have not been validated.
- Confirm template permission, report integration, risk methodology, and
  retention policy before implementing the remaining workflow. Do not rely on
  this prototype for final reporting.

## Third-party software

The extension bundles SnakeYAML 2.5, licensed under Apache License 2.0; its
licence text is included in the JAR under `META-INF/LICENSE-SnakeYAML.txt`.
The Montoya API is a compile-only dependency supplied by Burp at runtime.
