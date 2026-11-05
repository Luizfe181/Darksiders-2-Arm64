package com.vigil.darksiders2;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;

/**
 * Pre-game setup: pick the folder that holds media/media.upak and, optionally,
 * a custom Vulkan driver (Mesa Turnip).
 *
 * Why this screen exists: the runtime reads its settings from a config.ini in
 * the app's internal storage (win32_stubs / main.cpp look there), and the game
 * folder must be a real filesystem path -- not a content:// URI -- because the
 * native side opens it with open().
 *
 * The driver is COPIED into the app's private storage: /sdcard is mounted
 * noexec on most devices, so dlopen() of a .so living there fails.
 */
public class SetupActivity extends Activity {

    private static final int REQ_FOLDER = 1;
    private static final int REQ_DRIVER = 2;
    private static final int REQ_STORAGE = 3;
    private static final int REQ_DXVK = 4;

    private static final String PREFS = "d2setup";
    private static final String KEY_PATH = "data_root";
    private static final String KEY_DRIVER = "driver";
    private static final String KEY_DXVK = "dxvk";
    private static final String DRIVER_FILE = "libvulkan_custom.so";
    private static final String DXVK_FILE = "libdxvk_d3d11.so";

    private SharedPreferences prefs;
    private TextView pathText, pathStatus, driverText, driverStatus, dxvkText, dxvkStatus, overall;
    private Button startButton;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_setup);

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        pathText = findViewById(R.id.pathText);
        pathStatus = findViewById(R.id.pathStatus);
        driverText = findViewById(R.id.driverText);
        driverStatus = findViewById(R.id.driverStatus);
        dxvkText = findViewById(R.id.dxvkText);
        dxvkStatus = findViewById(R.id.dxvkStatus);
        overall = findViewById(R.id.overall);
        startButton = findViewById(R.id.startButton);

        findViewById(R.id.pickFolder).setOnClickListener(v -> pickFolder());
        findViewById(R.id.pickDriver).setOnClickListener(v -> pickFile(REQ_DRIVER));
        findViewById(R.id.clearDriver).setOnClickListener(v -> {
            File driver = new File(new File(getFilesDir(), "drivers"), DRIVER_FILE);
            if (driver.exists()) driver.delete();
            prefs.edit().remove(KEY_DRIVER).apply();
            refresh();
        });
        findViewById(R.id.pickDxvk).setOnClickListener(v -> pickFile(REQ_DXVK));
        findViewById(R.id.clearDxvk).setOnClickListener(v -> {
            File dxvk = new File(new File(getFilesDir(), "dxvk"), DXVK_FILE);
            if (dxvk.exists()) dxvk.delete();
            prefs.edit().remove(KEY_DXVK).apply();
            refresh();
        });
        startButton.setOnClickListener(v -> startGame());

        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();   // the storage permission may have been granted meanwhile
    }

    // ---- game folder ------------------------------------------------------

    private void pickFolder() {
        ensureStorageAccess();
        Intent intent = new Intent(this, FolderPickerActivity.class);
        String current = prefs.getString(KEY_PATH, null);
        if (current != null) intent.putExtra(FolderPickerActivity.EXTRA_PATH, current);
        startActivityForResult(intent, REQ_FOLDER);
    }

    private File upakIn(String path) {
        if (path == null || path.isEmpty()) return null;
        File upak = new File(new File(path), "media/media.upak");
        return upak.isFile() ? upak : null;
    }

    // ---- custom driver ----------------------------------------------------

    private void pickDriver() {
        pickFile(REQ_DRIVER);
    }

    /** Shared file picker for the driver and for DXVK. */
    private void pickFile(int request) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        try {
            startActivityForResult(intent, request);
        } catch (ActivityNotFoundException e) {
            toast("Nenhuma aplicacao de ficheiros disponivel.");
        }
    }

    private void copyDriver(Uri uri) {
        File source = obtainSource(uri, Archive.Kind.VULKAN);
        if (source == null) return;

        File dir = new File(getFilesDir(), "drivers");
        if (!dir.exists() && !dir.mkdirs()) {
            toast("Nao foi possivel criar " + dir);
            return;
        }
        File target = new File(dir, DRIVER_FILE);
        if (!copyFile(source, target)) return;

        String arch = elfArch(target);
        if (!"arm64".equals(arch)) {
            target.delete();
            toast(arch == null ? "O ficheiro nao e uma biblioteca ELF."
                               : "Driver " + arch + ": este port e arm64-v8a.");
            refresh();
            return;
        }

        prefs.edit().putString(KEY_DRIVER, target.getAbsolutePath()).apply();
        toast("Driver instalado: " + target.getName());
        refresh();
    }

    private void copyDxvk(Uri uri) {
        File source = obtainSource(uri, Archive.Kind.DXVK);
        if (source == null) return;

        File dir = new File(getFilesDir(), "dxvk");
        if (!dir.exists() && !dir.mkdirs()) {
            toast("Nao foi possivel criar " + dir);
            return;
        }
        File target = new File(dir, DXVK_FILE);
        if (!copyFile(source, target)) return;

        String pe = peDescription(target);
        String arch = elfArch(target);
        if (!"arm64".equals(arch)) {
            target.delete();
            if (pe != null) {
                toast(pe + ": e um binario do Windows. Este port nao usa Wine — precisa de um "
                        + "libdxvk_d3d11.so ELF arm64.");
            } else if (arch == null) {
                toast("O ficheiro nao e uma biblioteca ELF.");
            } else {
                toast("DXVK " + arch + ": este port e arm64-v8a.");
            }
            refresh();
            return;
        }

        prefs.edit().putString(KEY_DXVK, target.getAbsolutePath()).apply();
        toast("DXVK instalado: " + target.getName());
        refresh();
    }

    /**
     * Turns the picked URI into a library file: a plain .so is copied as-is, a
     * .zip / .tar.gz is unpacked and the right member is picked out of it.
     * The result is temporary; the caller copies it to its final place.
     */
    private File obtainSource(Uri uri, Archive.Kind kind) {
        File work = new File(getCacheDir(), "unpack");
        Archive.deleteTree(work);
        if (!work.mkdirs() && !work.isDirectory()) {
            toast("Sem espaco para descompactar.");
            return null;
        }

        if (!Archive.isArchive(this, uri)) {
            File direct = new File(work, "picked.bin");
            if (!copyTo(uri, direct)) {
                Archive.deleteTree(work);
                return null;
            }
            return direct;
        }

        File packageDir = new File(work, "pkg");
        if (!Archive.extract(this, uri, packageDir)) {
            toast("Falha ao descompactar o pacote.");
            Archive.deleteTree(work);
            return null;
        }

        File library = Archive.findLibrary(packageDir, kind);
        if (library == null) {
            toast(kind == Archive.Kind.VULKAN
                    ? "Nenhum driver Vulkan (.so) dentro do pacote."
                    : "Nenhuma biblioteca DXVK dentro do pacote.");
            Archive.deleteTree(work);
            return null;
        }
        toast("Pacote descompactado: " + library.getName());
        return library;
    }

    private boolean copyFile(File source, File target) {
        try (InputStream in = new FileInputStream(source);
             OutputStream out = new FileOutputStream(target)) {
            byte[] buffer = new byte[1 << 16];
            int read;
            while ((read = in.read(buffer)) > 0) out.write(buffer, 0, read);
            return true;
        } catch (Exception e) {
            toast("Falha ao gravar: " + e.getMessage());
            return false;
        }
    }

    /** Copies a content:// URI into a real file in the app's storage. */
    private boolean copyTo(Uri uri, File target) {
        try (InputStream in = getContentResolver().openInputStream(uri);
             OutputStream out = new FileOutputStream(target)) {
            if (in == null) {
                toast("Falha ao abrir o ficheiro escolhido.");
                return false;
            }
            byte[] buffer = new byte[1 << 16];
            int read;
            while ((read = in.read(buffer)) > 0) out.write(buffer, 0, read);
            return true;
        } catch (Exception e) {
            toast("Falha ao copiar: " + e.getMessage());
            return false;
        }
    }

    /** "arm64", "x86_64", ... from the ELF header, or null if not an ELF. */
    private static String elfArch(File file) {
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            byte[] header = new byte[20];
            raf.readFully(header);
            if (header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F') {
                return null;
            }
            int machine = (header[18] & 0xFF) | ((header[19] & 0xFF) << 8);
            if (machine == 0xB7) return "arm64";   // EM_AARCH64
            if (machine == 0x3E) return "x86_64";  // EM_X86_64
            if (machine == 0x28) return "arm";     // EM_ARM
            return "machine 0x" + Integer.toHexString(machine);
        } catch (Exception e) {
            return null;
        }
    }

    /** "PE x86-64" / "PE ARM64" / ... from the PE header, or null if not a PE. */
    private static String peDescription(File file) {
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            byte[] dos = new byte[64];
            raf.readFully(dos);
            if (dos[0] != 'M' || dos[1] != 'Z') return null;
            int peOffset = (dos[0x3C] & 0xFF) | ((dos[0x3D] & 0xFF) << 8)
                    | ((dos[0x3E] & 0xFF) << 16) | ((dos[0x3F] & 0xFF) << 24);
            raf.seek(peOffset);
            byte[] header = new byte[6];
            raf.readFully(header);
            if (header[0] != 'P' || header[1] != 'E' || header[2] != 0 || header[3] != 0) {
                return "PE";
            }
            int machine = (header[4] & 0xFF) | ((header[5] & 0xFF) << 8);
            switch (machine) {
                case 0x8664: return "PE x86-64";
                case 0xAA64: return "PE ARM64";
                case 0x014C: return "PE i386";
                default: return "PE machine 0x" + Integer.toHexString(machine);
            }
        } catch (Exception e) {
            return null;
        }
    }

    // ---- state ------------------------------------------------------------

    private void refresh() {
        final String path = prefs.getString(KEY_PATH, null);
        final File upak = upakIn(path);
        final boolean ready = upak != null;

        if (path == null) {
            pathText.setText(R.string.setup_no_folder);
            pathStatus.setText("");
        } else {
            pathText.setText(path);
            if (ready) {
                long mb = Math.max(1, upak.length() / (1024 * 1024));
                pathStatus.setText("media/media.upak encontrado (" + mb + " MB)");
                pathStatus.setTextColor(0xFF81C995);
            } else {
                pathStatus.setText("media/media.upak nao encontrado aqui");
                pathStatus.setTextColor(0xFFF28B82);
            }
        }

        final String driver = prefs.getString(KEY_DRIVER, null);
        if (driver == null) {
            driverText.setText(R.string.setup_driver_system);
            driverStatus.setText("Sem driver customizado: usa o libvulkan.so do sistema.");
            driverStatus.setTextColor(0xFF9AA0A6);
        } else {
            driverText.setText(new File(driver).getName());
            driverStatus.setText("Turnip copiado para o armazenamento da app.");
            driverStatus.setTextColor(0xFF81C995);
        }

        startButton.setEnabled(ready);
        overall.setText(ready ? ""
                : "Escolha a pasta que contem media/media.upak para poder iniciar.");

        // DXVK: user-installed first, then whatever was packaged into the APK.
        final String userDxvk = prefs.getString(KEY_DXVK, null);
        final File packaged = new File(getApplicationInfo().nativeLibraryDir, "libdxvk_d3d11.so");
        if (userDxvk != null) {
            File file = new File(userDxvk);
            dxvkText.setText(file.getName());
            dxvkStatus.setText("DXVK fornecido pelo utilizador (" + (file.length() / 1024) + " KB).");
            dxvkStatus.setTextColor(0xFF81C995);
        } else if (packaged.isFile()) {
            dxvkText.setText("empacotado no APK");
            dxvkStatus.setText("DXVK incluido no build (" + (packaged.length() / 1024) + " KB).");
            dxvkStatus.setTextColor(0xFF81C995);
        } else {
            dxvkText.setText(R.string.setup_dxvk_none);
            dxvkStatus.setText("Sem DXVK: as chamadas D3D11 nao serao atendidas.");
            dxvkStatus.setTextColor(0xFFF28B82);
        }
    }

    private void startGame() {
        String path = prefs.getString(KEY_PATH, null);
        if (upakIn(path) == null) {
            refresh();
            return;
        }
        writeConfig(path, prefs.getString(KEY_DRIVER, null), prefs.getString(KEY_DXVK, null));
        startActivity(new Intent(this, Darksiders2Activity.class));
    }

    /** The file the native side reads: getFilesDir()/config.ini. */
    private void writeConfig(String dataRoot, String driver, String dxvk) {
        File ini = new File(getFilesDir(), "config.ini");
        StringBuilder text = new StringBuilder();
        text.append("; gerado pela tela de configuracao\n");
        text.append("data_root=").append(dataRoot).append('\n');
        if (driver != null) text.append("custom_driver=").append(driver).append('\n');
        if (dxvk != null) text.append("dxvk_library=").append(dxvk).append('\n');
        try (FileWriter writer = new FileWriter(ini, false)) {
            writer.write(text.toString());
        } catch (Exception e) {
            toast("Falha ao escrever config.ini: " + e.getMessage());
        }
    }

    // ---- permissions ------------------------------------------------------

    private void ensureStorageAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    startActivity(new Intent(
                            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:" + getPackageName())));
                } catch (Exception e) {
                    try {
                        startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                    } catch (Exception ignored) {
                        toast("Conceda 'Acesso a todos os ficheiros' nas definicoes.");
                    }
                }
            }
        } else if (checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.READ_EXTERNAL_STORAGE}, REQ_STORAGE);
        }
    }

    // ---- results ----------------------------------------------------------

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK || data == null) return;

        if (request == REQ_FOLDER) {
            String path = data.getStringExtra(FolderPickerActivity.EXTRA_PATH);
            if (path != null) prefs.edit().putString(KEY_PATH, path).apply();
            refresh();
        } else if (request == REQ_DRIVER && data.getData() != null) {
            copyDriver(data.getData());
        } else if (request == REQ_DXVK && data.getData() != null) {
            copyDxvk(data.getData());
        }
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }
}
