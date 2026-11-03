// Set by VmThings after "Set up hosting" (see the Host button at the bottom of the site).
// Visitors use this public key to check they're talking to the real host, so nobody
// else can pretend to be the server. It is safe to publish. Leave null until set up.
export const HOST_PUBLIC_KEY = null;

// Optional: your own PeerJS server or extra STUN/TURN servers if some visitors can't connect.
export const PEER_OPTIONS = {
  // host: "peer.example.com", port: 443, secure: true, path: "/",
  // config: { iceServers: [{ urls: "stun:stun.l.google.com:19302" }, { urls: "turn:...", username: "...", credential: "..." }] }
};
