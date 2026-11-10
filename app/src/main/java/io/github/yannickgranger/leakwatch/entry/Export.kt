package io.github.yannickgranger.leakwatch.entry

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

object Export {
    fun zip(context: Context): File? {
        val root = Capture.archiveRoot(context)
        val files = root.walkTopDown().filter { it.isFile && !it.name.endsWith(".tmp") }.toList()
        if (files.isEmpty()) return null
        val dir = File(context.cacheDir, "export").also { it.mkdirs() }
        val out = File(dir, "leakwatch-archive.zip")
        ZipOutputStream(out.outputStream().buffered()).use { zip ->
            for (f in files) {
                zip.putNextEntry(ZipEntry("archive/" + f.relativeTo(root).path))
                f.inputStream().use { it.copyTo(zip) }
                zip.closeEntry()
            }
        }
        return out
    }

    fun shareIntent(context: Context, file: File, title: String): Intent {
        val uri = FileProvider.getUriForFile(context, context.packageName + ".files", file)
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/zip")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        return Intent.createChooser(send, title)
    }
}
