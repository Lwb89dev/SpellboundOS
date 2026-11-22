package dev.spellboundfit;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import dev.spellboundfit.ble.BleWatchClient;
import dev.spellboundfit.protocol.Protocol;
import dev.spellboundfit.roadstr.RoadstrParser;
import dev.spellboundfit.service.WatchNotificationListener;
import java.util.Arrays;
import java.util.TimeZone;

/**
 * SpellboundFit Android companion entry screen: link status, watch telemetry,
 * notification-bridge permission shortcut and test controls.
 */
public final class MainActivity extends Activity implements BleWatchClient.Listener {
    private BleWatchClient watchClient;
    private TextView statusView;
    private TextView telemetryView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        byte[] defaultPsk = new byte[32];
        for (int i = 0; i < 32; i++) defaultPsk[i] = (byte) (0x40 + i);
        watchClient = new BleWatchClient(defaultPsk);
        watchClient.setListener(this);
        WatchNotificationListener.attachClient(watchClient);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 64, 48, 48);

        TextView header = new TextView(this);
        header.setText("SpellboundFit Companion");
        header.setTextSize(22f);
        root.addView(header);

        statusView = new TextView(this);
        statusView.setText("Watch: disconnected");
        root.addView(statusView);

        telemetryView = new TextView(this);
        telemetryView.setText("Telemetry: --");
        root.addView(telemetryView);

        Button btnNotifPerm = new Button(this);
        btnNotifPerm.setText("Enable Notification Bridge");
        btnNotifPerm.setOnClickListener(v ->
                startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)));
        root.addView(btnNotifPerm);

        Button btnSyncTime = new Button(this);
        btnSyncTime.setText("Sync Time");
        btnSyncTime.setOnClickListener(v -> {
            long unixSec = System.currentTimeMillis() / 1000L;
            int tzMin = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60000;
            watchClient.sendFrame(Protocol.encodeTimeSync(watchClient.nextSeq(), unixSec, tzMin));
        });
        root.addView(btnSyncTime);

        Button btnTestNotif = new Button(this);
        btnTestNotif.setText("Send Test Notification");
        btnTestNotif.setOnClickListener(v -> watchClient.sendFrame(
                Protocol.encodeNotifyPost(
                        watchClient.nextSeq(), 1001L, System.currentTimeMillis() / 1000L,
                        "SpellboundFit", "Test Alert", "Bridge active",
                        Arrays.asList("OK", "Dismiss"))));
        root.addView(btnTestNotif);

        Button btnTestRoadstr = new Button(this);
        btnTestRoadstr.setText("Send Test Roadstr Turn");
        btnTestRoadstr.setOnClickListener(v -> {
            RoadstrParser.NavInstruction nav = RoadstrParser.parse(
                    "Roadstr", "Svolta a destra tra 200 m su Via Emilia (Arrivo 7 min)");
            if (nav != null) {
                watchClient.sendFrame(nav.toFrame(watchClient.nextSeq()));
            }
        });
        root.addView(btnTestRoadstr);

        setContentView(root);
    }

    @Override
    public void onConnectionChanged(boolean connected, boolean encrypted) {
        runOnUiThread(() -> statusView.setText(
                connected ? (encrypted ? "Watch: connected (encrypted)" : "Watch: handshaking")
                          : "Watch: disconnected"));
    }

    @Override
    public void onTelemetry(Protocol.Telemetry t) {
        runOnUiThread(() -> telemetryView.setText(
                "Battery: " + t.batteryPct + "%" + (t.charging ? " (chg)" : "")
                + " | Steps: " + t.steps + " | HR: " + t.hrBpm + " bpm"));
    }

    @Override
    public void onNotifyAction(Protocol.NotifyActionEvent event) {
        WatchNotificationListener.executeWatchAction(event);
    }
}
