package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import org.slf4j.Logger;

/**
 * Plugin-message plumbing for in-place mode: registers the two veloauth channels, swallows
 * them so they never reach a real client or backend by accident, and routes the backend's
 * signed ACK to the connection that owns the pending unlock.
 *
 * <p>Both channels are consumed here in every direction. A client that sends on
 * {@code veloauth:unlock} or {@code veloauth:ack} is dropped at the proxy instead of being
 * forwarded; the ACK from a backend is never forwarded to the client either (a real client has
 * no handler for it). Only an ACK that arrives from a backend {@link ServerConnection} is
 * looked at, and it is still subject to HMAC, UUID and nonce verification in the coordinator.
 */
public final class InPlaceUnlockChannelListener {

    private final ConnectionManager connectionManager;
    private final Logger logger;

    public InPlaceUnlockChannelListener(ConnectionManager connectionManager, Logger logger) {
        this.connectionManager = connectionManager;
        this.logger = logger;
    }

    public void registerChannels(ProxyServer server) {
        server.getChannelRegistrar().register(InPlaceUnlocker.CHANNEL, InPlaceUnlocker.ACK_CHANNEL);
    }

    public void unregisterChannels(ProxyServer server) {
        server.getChannelRegistrar().unregister(InPlaceUnlocker.CHANNEL, InPlaceUnlocker.ACK_CHANNEL);
    }

    @Subscribe
    public void onPluginMessage(PluginMessageEvent event) {
        boolean isUnlock = InPlaceUnlocker.CHANNEL.equals(event.getIdentifier());
        boolean isAck = InPlaceUnlocker.ACK_CHANNEL.equals(event.getIdentifier());
        if (!isUnlock && !isAck) {
            return;
        }
        // Consumed here, always: never forwarded in either direction.
        event.setResult(PluginMessageEvent.ForwardResult.handled());

        if (!isAck) {
            return;
        }
        if (!(event.getSource() instanceof ServerConnection backend)) {
            // A client sent on the ACK channel. It cannot hold the secret; drop it.
            logger.debug("Dropped a veloauth:ack message that did not come from a backend");
            return;
        }
        connectionManager.handleInPlaceUnlockAck(backend.getPlayer(), event.getData());
    }
}
