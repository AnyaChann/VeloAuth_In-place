package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.CookieReceiveEvent;
import com.velocitypowered.api.proxy.Player;

/**
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
 */
final class SessionCookieListener {

    private final CommandContext ctx;

    SessionCookieListener(CommandContext ctx) {
        this.ctx = ctx;
    }

    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        if (!ctx.settings().isSessionCookieEnabled()) {
            return;
        }
        Player player = event.getPlayer();
        if (player.isOnlineMode()) {
            // Premium accounts are verified by Mojang on every connection already; there is no
            // password step for a cookie to ever substitute for.
            return;
        }
        player.requestCookie(SessionCookieCodec.COOKIE_KEY);
    }

    @Subscribe
    public void onCookieReceive(CookieReceiveEvent event) {
        if (!ctx.settings().isSessionCookieEnabled()) {
            return;
        }
        if (!SessionCookieCodec.COOKIE_KEY.equals(event.getOriginalKey())) {
            return;
        }
        byte[] data = event.getOriginalData();
        if (data == null || data.length == 0) {
            return;
        }
        LoginCommand.attemptCookieLogin(ctx, event.getPlayer(), data);
    }
}