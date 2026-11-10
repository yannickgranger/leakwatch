package io.github.yannickgranger.leakwatch.domain

class ByteQueue(initial: Int = 4096) {
    var array = ByteArray(initial)
        private set
    var start = 0
        private set
    var size = 0
        private set

    fun append(data: ByteArray, off: Int = 0, len: Int = data.size) {
        if (len <= 0) return
        if (start + size + len > array.size) {
            if (size + len <= array.size && start > 0) {
                array.copyInto(array, 0, start, start + size)
            } else {
                var cap = array.size
                while (cap < size + len) cap *= 2
                val grown = ByteArray(cap)
                array.copyInto(grown, 0, start, start + size)
                array = grown
            }
            start = 0
        }
        data.copyInto(array, start + size, off, off + len)
        size += len
    }

    fun drop(n: Int) {
        val k = n.coerceIn(0, size)
        start += k
        size -= k
        if (size == 0) start = 0
    }

    fun copy(from: Int, len: Int): ByteArray = array.copyOfRange(start + from, start + from + len)
}
