package dev.spellboundfit;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import dev.spellboundfit.ble.BleWatchClient;
import dev.spellboundfit.protocol.Protocol;
import dev.spellboundfit.roadstr.RoadstrParser;
import dev.spellboundfit.service.WatchNotificationListener;
import java.util.Arrays;
import java.util.TimeZone;

/**
 * SpellboundFit Android companion dashboard: BLE scan/connect, PSK config,
 * live watch telemetry, notification-bridge shortcut and test senders.
 */
public final class MainActivity extends Activity implements BleWatchClient.Listener {
    private static final String PREFS_NAME = "spellboundfit_prefs";
    private static final String KEY_PSK_HEX = "psk_hex";
    private static final String KEY_MAC = "watch_mac";
    private static final int REQ_BLE_PERMS = 1001;

    private BleWatchClient watchClient;
    private BluetoothAdapter btAdapter;
    private BluetoothLeScanner leScanner;
    private boolean scanning;

    private TextView statusView;
    private TextView telemetryView;
    private TextView scanLogView;
    private EditText macInput;
    private EditText pskInput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String savedMac = prefs.getString(KEY_MAC, "");
        String savedPskHex = prefs.getString(KEY_PSK_HEX, defaultPskHex());

        BluetoothManager bm = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        if (bm != null) {
            btAdapter = bm.getAdapter();
        }

        initClient(parseHexOrDefault(savedPskHex));

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 64, 48, 64);
        scroll.addView(root);

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

        macInput = new EditText(this);
        macInput.setHint("Watch BLE MAC (AA:BB:CC:DD:EE:FF)");
        macInput.setText(savedMac);
        root.addView(macInput);

        pskInput = new EditText(this);
        pskInput.setHint("32-byte PSK (64 hex chars)");
        pskInput.setText(savedPskHex);
        root.addView(pskInput);

        Button btnScan = new Button(this);
        btnScan.setText("Scan BLE Watches");
        btnScan.setOnClickListener(v -> toggleBleScan());
        root.addView(btnScan);

        Button btnConnect = new Button(this);
        btnConnect.setText("Connect Watch (Encrypted)");
        btnConnect.setOnClickListener(v -> connectByMac());
        root.addView(btnConnect);

        Button btnDisconnect = new Button(this);
        btnDisconnect.setText("Disconnect");
        btnDisconnect.setOnClickListener(v -> watchClient.disconnect());
        root.addView(btnDisconnect);

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

        Button btnTestCall = new Button(this);
        btnTestCall.setText("Send Test Incoming Call");
        btnTestCall.setOnClickListener(v -> watchClient.sendFrame(
                Protocol.encodeCallState(watchClient.nextSeq(),
                        Protocol.CALL_RINGING, "Spellbound Test", "+3900000000")));
        root.addView(btnTestCall);

        scanLogView = new TextView(this);
        scanLogView.setText("BLE scan log: idle");
        root.addView(scanLogView);

        setContentView(scroll);
    }

    @Override
    protected void onDestroy() {
        stopBleScan();
        if (watchClient != null) {
            watchClient.disconnect();
        }
        super.onDestroy();
    }

    private void initClient(byte[] psk) {
        if (watchClient != null) {
            watchClient.disconnect();
        }
        watchClient = new BleWatchClient(psk);
        watchClient.setListener(this);
        WatchNotificationListener.attachClient(watchClient);
    }

    private boolean ensureBlePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            boolean scanOk = checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)
                    == PackageManager.PERMISSION_GRANTED;
            boolean connOk = checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                    == PackageManager.PERMISSION_GRANTED;
            if (!scanOk || !connOk) {
                requestPermissions(new String[]{
                        Manifest.permission.BLUETOOTH_SCAN,
                        Manifest.permission.BLUETOOTH_CONNECT
                }, REQ_BLE_PERMS);
                return false;
            }
        }
        return true;
    }

    private void toggleBleScan() {
        if (scanning) {
            stopBleScan();
            return;
        }
        if (btAdapter == null || !btAdapter.isEnabled()) {
            scanLogView.setText("BLE scan: Bluetooth disabled");
            return;
        }
        if (!ensureBlePermissions()) return;
        leScanner = btAdapter.getBluetoothLeScanner();
        if (leScanner == null) {
            scanLogView.setText("BLE scan: scanner unavailable");
            return;
        }
        scanning = true;
        scanLogView.setText("BLE scan: scanning...");
        leScanner.startScan(scanCallback);
    }

    private void stopBleScan() {
        if (scanning && leScanner != null) {
            try {
                leScanner.stopScan(scanCallback);
            } catch (SecurityException ignored) {
            }
        }
        scanning = false;
    }

    private void connectByMac() {
        if (btAdapter == null || !btAdapter.isEnabled()) {
            statusView.setText("Watch: Bluetooth disabled");
            return;
        }
        if (!ensureBlePermissions()) return;
        stopBleScan();

        String mac = macInput.getText().toString().trim().toUpperCase(java.util.Locale.ROOT);
        String pskHex = pskInput.getText().toString().trim();
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                .putString(KEY_MAC, mac)
                .putString(KEY_PSK_HEX, pskHex)
                .apply();

        initClient(parseHexOrDefault(pskHex));
        try {
            BluetoothDevice dev = btAdapter.getRemoteDevice(mac);
            statusView.setText("Watch: connecting to " + mac + "...");
            watchClient.connect(this, dev);
        } catch (IllegalArgumentException e) {
            statusView.setText("Watch: invalid MAC address");
        }
    }

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            BluetoothDevice dev = result.getDevice();
            if (dev == null) return;
            String addr = dev.getAddress();
            String name = null;
            try {
                name = dev.getName();
            } catch (SecurityException ignored) {
            }
            if (name != null && (name.contains("Spellbound") || name.contains("Bip"))) {
                final String foundName = name;
                runOnUiThread(() -> {
                    macInput.setText(addr);
                    scanLogView.setText("Found: " + foundName + " (" + addr + ")");
                });
                stopBleScan();
            }
        }
    };

    private static String defaultPskHex() {
        StringBuilder sb = new StringBuilder(64);
        for (int i = 0; i < 32; i++) {
            sb.append(String.format(java.util.Locale.ROOT, "%02x", 0x40 + i));
        }
        return sb.toString();
    }

    private static byte[] parseHexOrDefault(String hex) {
        if (hex != null && hex.length() == 64) {
            try {
                byte[] out = new byte[32];
                for (int i = 0; i < 32; i++) {
                    out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                }
                return out;
            } catch (NumberFormatException ignored) {
            }
        }
        byte[] def = new byte[32];
        for (int i = 0; i < 32; i++) def[i] = (byte) (0x40 + i);
        return def;
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
