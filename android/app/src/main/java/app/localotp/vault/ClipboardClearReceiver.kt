package app.localotp.vault

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.SystemClock

/**
 * Clears a copied code even when the app process was frozen or killed after
 * copying. Not exported; only this app's own alarm can trigger it. The alarm
 * is inexact (no special permission), so it may fire somewhat later.
 */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        VaultController.clearClipboardLabelled(context.getSystemService(ClipboardManager::class.java))
    }

    companion object {
        private fun intent(context: Context) = PendingIntent.getBroadcast(
            context,
            0,
            Intent(context, ClipboardClearReceiver::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        fun schedule(context: Context, delayMs: Long) {
            context.getSystemService(AlarmManager::class.java)
                .set(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + delayMs, intent(context))
        }

        fun cancel(context: Context) {
            context.getSystemService(AlarmManager::class.java).cancel(intent(context))
        }
    }
}
