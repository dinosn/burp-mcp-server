package net.portswigger.mcp.tools

import burp.api.montoya.scanner.ScanTask
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory registry for started Scanner tasks (Audits/Crawls).
 * Keys are randomly generated UUID strings; values are ScanTask instances.
 */
object ScannerTaskRegistry {
    private val idToTask: MutableMap<String, ScanTask> = ConcurrentHashMap()

    fun put(task: ScanTask): String {
        val id = UUID.randomUUID().toString()
        idToTask[id] = task
        return id
    }

    fun get(id: String): ScanTask? = idToTask[id]

    fun remove(id: String): ScanTask? = idToTask.remove(id)

    fun clear() {
        idToTask.clear()
    }
}


