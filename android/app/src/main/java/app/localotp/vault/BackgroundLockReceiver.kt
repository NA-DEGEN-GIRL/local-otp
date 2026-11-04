package app.localotp.vault

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import app.localotp.LocalOtpApp

/**
 * Locks the vault 30 seconds after the app left the foreground, even when the
 * process was frozen meanwhile (a Handler timer never runs in a frozen
 * process; an alarm unfreezes it). Not exported; only our own alarm fires it.
 * If the process was killed instead, there is nothing in memory to wipe.
 */
class BackgroundLockReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        (context.applicationContext as? LocalOtpApp)?.vault?.lock(VaultController.LOCKED_BACKGROUND)
    }

    companion object {
        private fun intent(context: Context) = PendingIntent.getBroadcast(
            context,
            0,
            Intent(context, BackgroundLockReceiver::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        fun schedule(context: Context, delayMs: Long) {
            context.getSystemService(AlarmManager::class.java).setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + delayMs,
                intent(context),
            )
        }

        fun cancel(context: Context) {
            context.getSystemService(AlarmManager::class.java).cancel(intent(context))
        }
    }
}
