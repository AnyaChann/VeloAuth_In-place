package net.rafalohaki.veloauth.connection;

/** Internal disposition whose {@link #accepted()} flag preserves the legacy gateway contract. */
enum BackendTransferOutcome {
    CONNECTED(true),
    /**
     * In-place mode has accepted the unlock workflow and is waiting for backend acknowledgement.
     * This is deliberately distinct from CONNECTED: sendPluginMessage() is not completion.
     */
    WAITING_FOR_UNLOCK(true),
    COALESCED(true),
    WAITING_FOR_BACKEND(true),
    FALLBACK_TO_AUTH(true),
    RETRYING_TIMEOUT(true),
    REJECTED(false);

    private final boolean accepted;

    BackendTransferOutcome(boolean accepted) {
        this.accepted = accepted;
    }

    boolean accepted() {
        return accepted;
    }
}
