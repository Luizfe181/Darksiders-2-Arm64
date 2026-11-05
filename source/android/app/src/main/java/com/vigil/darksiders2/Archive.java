package com.vigil.darksiders2;

import android.content.Context;
import android.net.Uri;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Unpacks the packages people actually download: a Turnip driver comes as a
 * .zip (often with the .so buried in a subfolder, next to meta.json), and a DXVK
 * release as a .tar.gz with x64/ and x32/ trees.
 *
 * No third-party dependency: ZipInputStream for the zip, a small tar reader on
 * top of GZIPInputStream for the tarball. Both write into one directory and
 * refuse entries that would escape it.
 */
final class Archive {

    enum Kind { VULKAN, DXVK }

    private static final long MAX_TOTAL = 1L << 30;   // 1 GiB, guard against bombs
    private static final int MAX_ENTRIES = 20000;

    private Archive() {}

    /** True if the picked file starts like a zip or a gzip stream. */
    static boolean isArchive(Context context, Uri uri) {
        try (InputStream in = context.getContentResolver().openInputStream(uri)) {
            if (in == null) return false;
            byte[] magic = new byte[4];
            int read = in.read(magic);
            if (read >= 2 && (magic[0] & 0xFF) == 0x1F && (magic[1] & 0xFF) == 0x8B) return true;
            return read >= 4 && magic[0] == 'P' && magic[1] == 'K' && magic[2] == 3 && magic[3] == 4;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean extract(Context context, Uri uri, File destination) {
        InputStream raw = null;
        try {
            raw = context.getContentResolver().openInputStream(uri);
            if (raw == null) return false;

            PushbackInputStream in = new PushbackInputStream(raw, 4);
            byte[] magic = new byte[4];
            int read = in.read(magic);
            if (read > 0) in.unread(magic, 0, read);

            if (read >= 2 && (magic[0] & 0xFF) == 0x1F && (magic[1] & 0xFF) == 0x8B) {
                return untar(new GZIPInputStream(in), destination);
            }
            if (read >= 4 && magic[0] == 'P' && magic[1] == 'K') {
                return unzip(in, destination);
            }
            return false;
        } catch (Exception e) {
            return false;
        } finally {
            try {
                if (raw != null) raw.close();
            } catch (Exception ignored) {
            }
        }
    }

    // ---- zip --------------------------------------------------------------

    private static boolean unzip(InputStream in, File destination) throws Exception {
        long total = 0;
        int entries = 0;
        try (ZipInputStream zip = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES) return false;
                File target = safeTarget(destination, entry.getName());
                if (target == null) continue;
                if (entry.isDirectory()) {
                    target.mkdirs();
                    continue;
                }
                File parent = target.getParentFile();
                if (parent != null && !parent.exists()) parent.mkdirs();
                total += copyStream(zip, target, MAX_TOTAL - total);
                if (total >= MAX_TOTAL) return false;
            }
        }
        return true;
    }

    // ---- tar.gz -----------------------------------------------------------

    private static boolean untar(InputStream in, File destination) throws Exception {
        byte[] header = new byte[512];
        long total = 0;
        int entries = 0;

        while (true) {
            if (!readFully(in, header, 512)) break;
            if (isZeroBlock(header)) break;  // end of archive

            String name = cString(header, 0, 100);
            if (name.isEmpty()) break;

            long size = parseOctal(header, 124, 12);
            char type = (char) (header[156] & 0xFF);
            boolean isFile = type == '0' || type == 0 || type == '7';
            boolean isDir = type == '5';

            File target = safeTarget(destination, name);
            if (target != null) {
                if (isDir) {
                    target.mkdirs();
                } else if (isFile) {
                    File parent = target.getParentFile();
                    if (parent != null && !parent.exists()) parent.mkdirs();
                    total += copyStreamLimited(in, target, size, MAX_TOTAL - total);
                    if (total >= MAX_TOTAL) return false;
                    skipPadding(in, size);
                    continue;
                }
            }
            // Whatever it was, the payload has to be stepped over.
            if (!isDir) {
                skipFully(in, size + padding(size));
            }
            if (++entries > MAX_ENTRIES) return false;
        }
        return true;
    }

    // ---- helpers ----------------------------------------------------------

    /** Resolves an archive entry inside {@code root}, or null if it escapes. */
    private static File safeTarget(File root, String name) {
        if (name == null) return null;
        String clean = name.replace('\\', '/');
        while (clean.startsWith("./")) clean = clean.substring(2);
        if (clean.isEmpty() || clean.startsWith("/") || clean.contains("..")) return null;
        return new File(root, clean);
    }

    private static long copyStream(InputStream in, File target, long limit) throws Exception {
        try (OutputStream out = new FileOutputStream(target)) {
            byte[] buffer = new byte[1 << 16];
            long written = 0;
            int read;
            while ((read = in.read(buffer)) > 0) {
                written += read;
                if (written > limit) throw new Exception("archive too large");
                out.write(buffer, 0, read);
            }
            return written;
        }
    }

    /** Copies exactly {@code size} bytes (tar entry payload). */
    private static long copyStreamLimited(InputStream in, File target, long size, long limit)
            throws Exception {
        if (size > limit) throw new Exception("archive too large");
        try (OutputStream out = new FileOutputStream(target)) {
            byte[] buffer = new byte[1 << 16];
            long remaining = size;
            while (remaining > 0) {
                int want = (int) Math.min(buffer.length, remaining);
                int read = in.read(buffer, 0, want);
                if (read <= 0) throw new Exception("truncated tar entry");
                out.write(buffer, 0, read);
                remaining -= read;
            }
            return size;
        }
    }

    private static void skipPadding(InputStream in, long size) throws Exception {
        skipFully(in, padding(size));
    }

    private static long padding(long size) {
        long remainder = size % 512;
        return remainder == 0 ? 0 : 512 - remainder;
    }

    private static boolean readFully(InputStream in, byte[] buffer, int length) throws Exception {
        int offset = 0;
        while (offset < length) {
            int read = in.read(buffer, offset, length - offset);
            if (read < 0) return false;
            offset += read;
        }
        return true;
    }

    private static void skipFully(InputStream in, long count) throws Exception {
        long remaining = count;
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) {
                if (in.read() < 0) return;
                skipped = 1;
            }
            remaining -= skipped;
        }
    }

    private static boolean isZeroBlock(byte[] block) {
        for (byte b : block) {
            if (b != 0) return false;
        }
        return true;
    }

    private static String cString(byte[] block, int offset, int length) {
        int end = offset;
        while (end < offset + length && block[end] != 0) end++;
        return new String(block, offset, end - offset).trim();
    }

    private static long parseOctal(byte[] block, int offset, int length) {
        long value = 0;
        for (int i = offset; i < offset + length; i++) {
            int c = block[i] & 0xFF;
            if (c == 0 || c == ' ') continue;
            if (c < '0' || c > '7') break;
            value = value * 8 + (c - '0');
        }
        return value;
    }

    // ---- picking the library out of the package ---------------------------

    /**
     * Finds the library a package is meant to provide.
     *
     * Turnip packages name it libvulkan_freedreno.so (sometimes under drivers/).
     * The official DXVK release is a different shape: dxvk-<ver>/x64/d3d11.dll
     * and dxvk-<ver>/x32/*.dll, all PE images. The 64-bit d3d11.dll is returned
     * in that case so the caller can explain what was found -- picking x32 by
     * accident would be worse than useless.
     */
    static File findLibrary(File root, Kind kind) {
        if (kind == Kind.VULKAN) {
            File named = findByPredicate(root, f -> {
                String n = f.getName().toLowerCase(Locale.ROOT);
                return n.endsWith(".so") && (n.contains("vulkan") || n.contains("freedreno"));
            });
            if (named != null) return named;
            return findByPredicate(
                    root, f -> f.getName().toLowerCase(Locale.ROOT).endsWith(".so"));
        }

        // DXVK: prefer the 64-bit build of d3d11.dll inside x64/.
        File x64 = findByPredicate(root, f -> {
            String path = f.getAbsolutePath().replace('\\', '/').toLowerCase(Locale.ROOT);
            return path.contains("/x64/") && f.getName().equalsIgnoreCase("d3d11.dll");
        });
        if (x64 != null) return x64;

        // A native (ELF) DXVK build, if one is ever provided.
        File nativeDxvk = findByPredicate(root, f -> {
            String n = f.getName().toLowerCase(Locale.ROOT);
            return n.endsWith(".so") && n.contains("dxvk");
        });
        if (nativeDxvk != null) return nativeDxvk;

        File anySo = findByPredicate(
                root, f -> f.getName().toLowerCase(Locale.ROOT).endsWith(".so"));
        if (anySo != null) return anySo;

        return findByPredicate(root, f -> f.getName().equalsIgnoreCase("d3d11.dll"));
    }

    private interface Predicate {
        boolean test(File file);
    }

    private static File findByPredicate(File dir, Predicate predicate) {
        File[] children = dir.listFiles();
        if (children == null) return null;
        // Shallow first: packages put the library at the root or one level down.
        for (File child : children) {
            if (child.isFile() && predicate.test(child)) return child;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                File found = findByPredicate(child, predicate);
                if (found != null) return found;
            }
        }
        return null;
    }

    static void deleteTree(File file) {
        if (file == null || !file.exists()) return;
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) deleteTree(child);
        }
        file.delete();
    }
}
