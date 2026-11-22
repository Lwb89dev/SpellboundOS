package dev.spellboundfit.service;

import android.app.Notification;
import android.app.PendingIntent;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import dev.spellboundfit.ble.BleWatchClient;
import dev.spellboundfit.protocol.Protocol;
import dev.spellboundfit.roadstr.RoadstrParser;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bridges Android notifications and Roadstr turn-by-turn navigation updates to
 * SpellboundOS, and executes watch-triggered notification actions on the phone.
 */
public final class WatchNotificationListener extends NotificationListenerService {
    private static volatile BleWatchClient activeClient;
    private static final Map<Long, PendingIntent[]> actionIntents = new ConcurrentHashMap<>();

    public static void attachClient(BleWatchClient client) {
        activeClient = client;
    }

    public static boolean executeWatchAction(Protocol.NotifyActionEvent event) {
        PendingIntent[] intents = actionIntents.get(event.notifId);
        if (intents == null || event.actionIndex < 0 || event.actionIndex >= intents.length) {
            return false;
        }
        try {
            intents[event.actionIndex].send();
            return true;
        } catch (PendingIntent.CanceledException e) {
            return false;
        }
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        BleWatchClient client = activeClient;
        if (client == null || sbn == null) return;

        Notification n = sbn.getNotification();
        if (n == null || n.extras == null) return;
        Bundle extras = n.extras;
        CharSequence titleCs = extras.getCharSequence(Notification.EXTRA_TITLE);
        CharSequence textCs = extras.getCharSequence(Notification.EXTRA_TEXT);
        String title = titleCs == null ? "" : titleCs.toString();
        String body = textCs == null ? "" : textCs.toString();
        String pkg = sbn.getPackageName() == null ? "app" : sbn.getPackageName();

        // Check Roadstr / navigation turn-by-turn guidance first.
        if (pkg.contains("roadstr") || pkg.contains("maps")) {
            RoadstrParser.NavInstruction nav = RoadstrParser.parse(title, body);
            if (nav != null) {
                client.sendFrame(nav.toFrame(client.nextSeq()));
                return;
            }
        }

        long id = (sbn.getId() & 0xFFFFFFFFL);
        if (id == 0) id = 1;
        List<String> labels = new ArrayList<>();
        if (n.actions != null && n.actions.length > 0) {
            int count = Math.min(n.actions.length, 4);
            PendingIntent[] intents = new PendingIntent[count];
            for (int i = 0; i < count; i++) {
                CharSequence lbl = n.actions[i].title;
                labels.add(lbl == null ? "Action" : lbl.toString());
                intents[i] = n.actions[i].actionIntent;
            }
            actionIntents.put(id, intents);
        }

        String appName = pkg.contains(".") ? pkg.substring(pkg.lastIndexOf('.') + 1) : pkg;
        long tsSec = sbn.getPostTime() / 1000L;
        byte[] frame = Protocol.encodeNotifyPost(
                client.nextSeq(), id, tsSec, appName, title, body, labels);
        client.sendFrame(frame);
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        BleWatchClient client = activeClient;
        if (client == null || sbn == null) return;
        String pkg = sbn.getPackageName() == null ? "" : sbn.getPackageName();
        if (pkg.contains("roadstr")) {
            client.sendFrame(Protocol.encodeNavClear(client.nextSeq()));
            return;
        }
        long id = (sbn.getId() & 0xFFFFFFFFL);
        if (id == 0) id = 1;
        actionIntents.remove(id);
        client.sendFrame(Protocol.encodeNotifyDismiss(client.nextSeq(), id));
    }
}
