package dev.spellboundfit.ble;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import dev.spellboundfit.protocol.Protocol;
import dev.spellboundfit.protocol.SecureLink;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * BLE GATT client speaking SpellboundFit v1 encrypted binary protocol.
 */
public final class BleWatchClient {
    public static final UUID SERVICE_UUID =
            UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e");
    public static final UUID CHAR_TX_UUID =
            UUID.fromString("6e400002-b5a3-f393-e0a9-e50e24dcca9e");
    public static final UUID CHAR_RX_UUID =
            UUID.fromString("6e400003-b5a3-f393-e0a9-e50e24dcca9e");
    public static final UUID CCCD_UUID =
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    public interface Listener {
        void onConnectionChanged(boolean connected, boolean encrypted);
        void onTelemetry(Protocol.Telemetry telemetry);
        void onNotifyAction(Protocol.NotifyActionEvent event);
    }

    private final SecureLink secureLink;
    private final Protocol.StreamDecoder decoder = new Protocol.StreamDecoder();
    private final AtomicInteger seqCounter = new AtomicInteger(0);
    private volatile Listener listener;
    private BluetoothGatt gatt;
    private BluetoothGattCharacteristic txChar;
    private boolean connected;

    public BleWatchClient(byte[] psk) {
        this.secureLink = new SecureLink(psk);
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public int nextSeq() {
        return seqCounter.incrementAndGet() & 0xFFFF;
    }

    public void connect(Context context, BluetoothDevice device) {
        disconnect();
        gatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE);
    }

    public void disconnect() {
        if (gatt != null) {
            gatt.close();
            gatt = null;
        }
        txChar = null;
        connected = false;
        notifyListener();
    }

    public boolean sendFrame(byte[] plainFrame) {
        if (gatt == null || txChar == null || !connected) {
            return false;
        }
        byte[] wire = secureLink.isEstablished() ? secureLink.encrypt(plainFrame) : plainFrame;
        return writeRaw(wire);
    }

    private boolean writeRaw(byte[] data) {
        if (gatt == null || txChar == null) return false;
        txChar.setValue(data);
        return gatt.writeCharacteristic(txChar);
    }

    private void notifyListener() {
        Listener l = this.listener;
        if (l != null) {
            l.onConnectionChanged(connected, secureLink.isEstablished());
        }
    }

    private void onRxBytes(byte[] packet) {
        if (packet == null || packet.length == 0) return;
        if (!secureLink.isEstablished() && packet[0] == SecureLink.MSG_HELLO_ACK) {
            try {
                secureLink.finishHandshake(packet);
                notifyListener();
            } catch (RuntimeException ignored) {
                disconnect();
            }
            return;
        }
        byte[] plain = secureLink.isEstablished() ? secureLink.decrypt(packet) : packet;
        List<Protocol.Frame> frames = decoder.feed(plain);
        Listener l = this.listener;
        if (l == null) return;
        for (Protocol.Frame f : frames) {
            if (f.type == Protocol.MSG_TELEMETRY) {
                l.onTelemetry(Protocol.decodeTelemetry(f.payload));
            } else if (f.type == Protocol.MSG_NOTIFY_ACTION) {
                l.onNotifyAction(Protocol.decodeNotifyAction(f.payload));
            }
        }
    }

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connected = true;
                g.requestMtu(247);
                notifyListener();
            } else {
                connected = false;
                txChar = null;
                notifyListener();
            }
        }

        @Override
        public void onMtuChanged(BluetoothGatt g, int mtu, int status) {
            g.discoverServices();
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) return;
            BluetoothGattService svc = g.getService(SERVICE_UUID);
            if (svc == null) return;
            txChar = svc.getCharacteristic(CHAR_TX_UUID);
            BluetoothGattCharacteristic rxChar = svc.getCharacteristic(CHAR_RX_UUID);
            if (rxChar != null) {
                g.setCharacteristicNotification(rxChar, true);
                BluetoothGattDescriptor cccd = rxChar.getDescriptor(CCCD_UUID);
                if (cccd != null) {
                    cccd.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    g.writeDescriptor(cccd);
                }
            }
            writeRaw(secureLink.buildHello(null));
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            onRxBytes(c.getValue());
        }
    };
}
