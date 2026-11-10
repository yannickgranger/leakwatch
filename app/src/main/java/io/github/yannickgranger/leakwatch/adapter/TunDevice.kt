package io.github.yannickgranger.leakwatch.adapter

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import io.github.yannickgranger.leakwatch.port.PacketSink
import io.github.yannickgranger.leakwatch.port.PacketSource

class TunDevice(private val pfd: ParcelFileDescriptor) : PacketSource, PacketSink {
    private val fd = pfd.fileDescriptor

    override fun read(buffer: ByteArray): Int = try {
        val n = Os.read(fd, buffer, 0, buffer.size)
        if (n < 0) -1 else n
    } catch (e: ErrnoException) {
        when (e.errno) {
            OsConstants.EAGAIN, OsConstants.EINTR -> 0
            else -> -1
        }
    } catch (e: java.io.InterruptedIOException) {
        0
    }

    override fun write(packet: ByteArray) {
        var attempts = 0
        while (attempts++ < 50) {
            try {
                Os.write(fd, packet, 0, packet.size)
                return
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR) return
                Thread.sleep(1)
            } catch (e: java.io.InterruptedIOException) {
                return
            }
        }
    }

    fun close() {
        runCatching { pfd.close() }
    }
}
