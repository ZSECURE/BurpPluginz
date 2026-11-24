package org.zsecure.burp.assistant;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;

final class TemplatePanel extends JPanel {
    private final DefaultListModel<TemplateImporter.Template> model = new DefaultListModel<>();
    private final JList<TemplateImporter.Template> list = new JList<>(model);
    private final JTextArea preview = new JTextArea();
    private final JTextArea diagnostics = new JTextArea(5, 40);
    private final JTextField search = new JTextField(22);
    private final JLabel count = new JLabel("No templates loaded");
    private final JButton load = new JButton("Load template directory");
    private List<TemplateImporter.Template> templates = List.of();

    TemplatePanel() {
        super(new BorderLayout());
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEADING));
        controls.add(load);
        JLabel searchLabel = new JLabel("Search:");
        searchLabel.setLabelFor(search);
        controls.add(searchLabel);
        controls.add(search);
        controls.add(count);
        add(controls, BorderLayout.NORTH);

        list.getAccessibleContext().setAccessibleName("Templates");
        preview.setEditable(false);
        preview.getAccessibleContext().setAccessibleName("Raw template preview");
        diagnostics.setEditable(false);
        diagnostics.getAccessibleContext().setAccessibleName("Import diagnostics");
        JSplitPane browser = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(list), new JScrollPane(preview));
        JSplitPane content = new JSplitPane(JSplitPane.VERTICAL_SPLIT, browser, new JScrollPane(diagnostics));
        content.setResizeWeight(0.8);
        add(content, BorderLayout.CENTER);

        load.addActionListener(event -> chooseDirectory());
        list.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                TemplateImporter.Template selected = list.getSelectedValue();
                preview.setText(selected == null ? "" : "ID: " + selected.id() + "\nCategory: "
                        + selected.category() + "\nCVSS: " + selected.cvss() + "\nSHA-256: "
                        + selected.sha256() + "\n\n" + selected.markdown());
                preview.setCaretPosition(0);
            }
        });
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
        });
    }

    private void chooseDirectory() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select the 08_web_application template directory");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path directory = chooser.getSelectedFile().toPath();
        load.setEnabled(false);
        count.setText("Importing...");
        new SwingWorker<TemplateImporter.Result, Void>() {
            protected TemplateImporter.Result doInBackground() throws Exception {
                return new TemplateImporter().importDirectory(directory);
            }

            protected void done() {
                try {
                    TemplateImporter.Result result = get();
                    templates = result.templates();
                    diagnostics.setText(String.join("\n", result.diagnostics()));
                    count.setText(templates.size() + " / " + TemplateImporter.IDS.size() + " templates");
                    filter();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    count.setText("Import interrupted");
                } catch (ExecutionException e) {
                    count.setText("Import failed");
                    diagnostics.setText("The selected directory could not be imported.");
                } finally {
                    load.setEnabled(true);
                }
            }
        }.execute();
    }

    private void filter() {
        String query = search.getText().toLowerCase(Locale.ROOT);
        model.clear();
        templates.stream().filter(template -> (template.id() + " " + template.title() + " "
                + template.category() + " " + template.cvss() + " " + template.markdown())
                .toLowerCase(Locale.ROOT).contains(query)).forEach(model::addElement);
    }
}
