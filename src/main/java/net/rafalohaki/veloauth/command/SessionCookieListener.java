package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.CookieReceiveEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.proxy.Player;

import java.util.concurrent.TimeUnit;

/**
 * EXPERIMENTAL - DO NOT ENABLE IN PRODUCTION. Reproducibly kicks players on at least one
 * modded backend with multiplayer.disconnect.unexpected_query_response, regardless of when
 * the cookie request fires relative to the connection lifecycle (confirmed to still happen
 * after a 15-second delay, ruling out a simple settling-time fix). Suspected protocol-level
 * conflict between Velocity's cookie packets (velocity-api 4.1.2-SNAPSHOT - itself an
 * unreleased snapshot) and the backend's own Minecraft-1.20.5-compatibility mods
 * (connector/packetfixer). Root cause not confirmed. Guarded by
 * session-cookie.enabled: false (default) and a startup WARN in SettingsValidator; do not
 * remove those guards without resolving the underlying conflict first.
 *
 * Wires Velocity's cookie protocol (Minecraft 1.20.5+, exposed via Player#requestCookie /
 * CookieReceiveEvent) into the session-cookie "remember me" feature: requests a stored cookie
 * right after an offline player's initial connection, and verifies whatever comes back via
 * LoginCommand#attemptCookieLogin.
 *
 * <p>Lives in this package (not .listener) rather than being a standalone top-level listener,
 * because it must share the exact same CommandContext instance as LoginCommand - CommandContext
 * holds its own per-instance command-lock map, so a second, separately constructed instance
 * would not coordinate with the real /login command's concurrency guards, which is a real
 * correctness requirement, not a style choice.
 *
 * <p>Purely additive: on any absence, expiry, or verification failure, this does nothing and
 * the player falls through to the completely unmodified normal /login prompt.
 *
 * <p>The cookie request is fired from ServerConnectedEvent, not PostLoginEvent. An earlier
 * version used PostLoginEvent (as soon as the player joined the proxy) and it collided with
 * Velocity's own backend-connection handshake for a modded server: the request landed while
 * Velocity was still exchanging LOGIN-phase custom queries with the backend (the mechanism
 * modded servers use to negotiate the mod list), and the backend kicked the player with
 * "multiplayer.disconnect.unexpected_query_response". ServerConnectedEvent fires only after
 * that handshake has fully completed and the player is in PLAY phase on the backend, which is
 * required for the PLAY-phase cookie protocol (Player#requestCookie/CookieReceiveEvent) to be
 * safe to use at all - the same class of "don't act before the connection has settled" timing
 * issue as BackendTransferCoordinator's auto-transfer-delay-ms buffer, just with a protocol
 * collision as the symptom instead of a silently-empty check.
 */
final class SessionCookieListener {

    private final CommandContext ctx;

    SessionCookieListener(CommandContext ctx) {
        this.ctx = ctx;
    }

    @Subscribe
    public void onServerConnected(ServerConnectedEvent event) {
        if (!ctx.settings().isSessionCookieEnabled()) {
            return;
        }
        Player player = event.getPlayer();
        if (player.isOnlineMode()) {
            // Premium accounts are verified by Mojang on every connection already; there is no
            // password step for a cookie to ever substitute for.
            return;
        }
        // ServerConnectedEvent firing does not guarantee every part of the connection has
        // settled (BackendTransferCoordinator hit an analogous issue: player.getCurrentServer()
        // could still read empty right after this same event for a modded backend). Reusing
        // the same auto-transfer-delay-ms buffer here is a deliberate hedge, not a proven
        // requirement - but given a bare ServerConnectedEvent hook already caused one live
        // protocol collision for this feature, waiting out the same settling window the rest
        // of in-place mode already relies on is cheaper than risking a second one.
        ctx.plugin().getServer().getScheduler()
                .buildTask(ctx.plugin(), () -> {
                    if (player.isActive()) {
                        player.requestCookie(SessionCookieCodec.COOKIE_KEY);
                    }
                })
                .delay(ctx.settings().getAutoTransferDelayMillis(), TimeUnit.MILLISECONDS)
                .schedule();
    }

    @Subscribe
    public void onCookieReceive(CookieReceiveEvent event) {
        if (!ctx.settings().isSessionCookieEnabled()) {
            return;
        }
        if (!SessionCookieCodec.COOKIE_KEY.equals(event.getOriginalKey())) {
            return;
        }
        // This cookie response is proxy-initiated (Player#requestCookie), not requested by the
        // backend, so it must never be forwarded downstream: Velocity's default result for any
        // CookieReceiveEvent is ForwardResult.forward(), and forwarding an unsolicited cookie
        // response to the modded backend is exactly what triggers
        // ServerCommonPacketListenerImpl#handleCookieResponse's DISCONNECT_UNEXPECTED_QUERY kick
        // (multiplayer.disconnect.unexpected_query_response) - even for an empty/no-cookie-found
        // response, so this must be set before the empty-data early return below.
        event.setResult(CookieReceiveEvent.ForwardResult.handled());
        byte[] data = event.getOriginalData();
        if (data == null || data.length == 0) {
            return;
        }
        LoginCommand.attemptCookieLogin(ctx, event.getPlayer(), data);
    }
}