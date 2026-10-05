package net.rafalohaki.veloauth.api.event;

import com.velocitypowered.api.proxy.Player;

import java.util.Objects;

/**
 * Fired once per connection when a player is authenticated <b>and</b> can actually play: they are on a backend
 * server (limbo mode) or the backend has acknowledged the in-place unlock (in-place mode).
 *
 * <p>It is fired with {@code fireAndForget}, so listeners can never delay or break the authentication flow, and it is
 * not fired again when the player later switches servers.
 *
 * <p>Other plugins can listen to it without depending on VeloAuth at compile time: the event only exposes plain
 * types ({@link String} and {@code boolean}) and is found by its class name.
 */
public final class PlayerAuthenticatedEvent {
    /** The player typed /login with the right password. */
    public static final String METHOD_LOGIN = "login";
    /** The player just created their account with /register. */
    public static final String METHOD_REGISTER = "register";
    /** The player passed the second factor (/2fa). */
    public static final String METHOD_TOTP = "totp";
    /** Mojang verified the connection (online mode), so no password was needed. */
    public static final String METHOD_PREMIUM = "premium";
    /** An earlier authentication of this player is still valid (same IP, session not expired). */
    public static final String METHOD_SESSION = "session";

    private final Player player;
    private final String method;
    private final boolean premium;
    private final String serverName;

    public PlayerAuthenticatedEvent(Player player, String method, boolean premium) {
        this(player, method, premium, null);
    }

    /**
     * @param serverName the backend server the player can play on; {@code null} when it is not known
     */
    public PlayerAuthenticatedEvent(Player player, String method, boolean premium, String serverName) {
        this.player = Objects.requireNonNull(player, "player");
        this.method = Objects.requireNonNull(method, "method");
        this.premium = premium;
        this.serverName = serverName == null ? "" : serverName;
    }

    public Player getPlayer() {
        return player;
    }

    /** One of the {@code METHOD_*} constants. */
    public String getMethod() {
        return method;
    }

    /** Whether Mojang verified this connection (online mode). */
    public boolean isPremium() {
        return premium;
    }

    /**
     * The backend server the player can play on (limbo mode: the one they just connected to; in-place mode: the one
     * that acknowledged the unlock), or an empty string when it is not known. The event can be delivered before
     * Velocity has finished moving the player there, so a listener that cares about the player's server should wait
     * until {@code player.getCurrentServer()} is this one.
     */
    public String getServerName() {
        return serverName;
    }

    @Override
    public String toString() {
        return "PlayerAuthenticatedEvent{player=" + player.getUsername() + ", method=" + method + ", premium=" + premium
                + ", server=" + serverName + '}';
    }
}