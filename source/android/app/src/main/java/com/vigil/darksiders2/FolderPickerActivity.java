package com.vigil.darksiders2;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Minimal directory browser over the real filesystem.
 *
 * The native side needs a real path (it opens media/media.upak with open()), so
 * the Storage Access Framework is not usable for the game folder -- a
 * content:// URI cannot be handed to open(). With MANAGE_EXTERNAL_STORAGE this
 * can walk /sdcard directly.
 */
public class FolderPickerActivity extends Activity {

    public static final String EXTRA_PATH = "path";

    private final List<File> entries = new ArrayList<>();
    private File current;
    private ListView list;
    private TextView pathView;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_folder_picker);

        list = findViewById(R.id.folderList);
        pathView = findViewById(R.id.currentPath);
        Button up = findViewById(R.id.upButton);
        Button choose = findViewById(R.id.chooseButton);

        current = startFromIntent();
        if (current == null || !current.isDirectory()) current = defaultStart();

        up.setOnClickListener(v -> {
            File parent = current.getParentFile();
            if (parent != null) enter(parent);
        });

        choose.setOnClickListener(v -> {
            Intent result = new Intent();
            result.putExtra(EXTRA_PATH, current.getAbsolutePath());
            setResult(RESULT_OK, result);
            finish();
        });

        list.setOnItemClickListener((parent, view, position, id) -> {
            File target = entries.get(position);
            if (target != null) enter(target);
        });

        enter(current);
    }

    private File startFromIntent() {
        String path = getIntent().getStringExtra(EXTRA_PATH);
        return path != null ? new File(path) : null;
    }

    private File defaultStart() {
        File external = Environment.getExternalStorageDirectory();
        if (external != null && external.isDirectory() && external.canRead()) return external;
        File app = getExternalFilesDir(null);
        return app != null ? app : new File("/");
    }

    private void enter(File dir) {
        current = dir;
        entries.clear();
        List<String> names = new ArrayList<>();

        File[] children = null;
        try {
            children = dir.listFiles();
        } catch (SecurityException e) {
            Toast.makeText(this, "Sem acesso a " + dir.getAbsolutePath(), Toast.LENGTH_LONG).show();
        }
        if (children != null) {
            Arrays.sort(children, (a, b) -> a.getName().compareToIgnoreCase(b.getName()));
            for (File child : children) {
                if (child.isDirectory() && !child.isHidden()) {
                    entries.add(child);
                    names.add("\uD83D\uDCC1  " + child.getName());
                }
            }
        }

        File parent = dir.getParentFile();
        if (parent != null) {
            entries.add(0, parent);
            names.add(0, "\u2B06  ..");
        }

        pathView.setText(dir.getAbsolutePath());
        list.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, names));
    }
}
