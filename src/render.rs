use crate::events::WgEvent;
use crate::interface::Interface;

// SSE fragments (compact HTML, safe to embed in SSE data fields)

pub fn table_html(iface: &Interface) -> String {
    let rows: String = iface.peers.iter().map(|peer| {
        let ips = peer.allowed_ips.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
        let ep = peer.endpoint.map(|e| e.to_string()).unwrap_or_else(|| "(none)".to_string());
        let key = &peer.public_key.0;
        format!(
            "<tr>\
              <td class='key'>{key}</td>\
              <td class='ip'>{ips}</td>\
              <td class='ep'>{ep}</td>\
              <td class='row-actions'>\
                <form action='/action/send' method='post' data-ajax>\
                  <input type='hidden' name='peer_key' value='{key}'>\
                  <button>Send</button>\
                </form>\
                <form action='/action/recv' method='post' data-ajax>\
                  <input type='hidden' name='peer_key' value='{key}'>\
                  <button>Recv</button>\
                </form>\
                <form action='/action/roam' method='post' data-ajax>\
                  <input type='hidden' name='peer_key' value='{key}'>\
                  <button>Roam</button>\
                </form>\
              </td>\
            </tr>"
        )
    }).collect();

    format!(
        "<table>\
          <thead><tr>\
            <th>Public Key</th>\
            <th>Allowed IPs</th>\
            <th>Endpoint (outer)</th>\
            <th></th>\
          </tr></thead>\
          <tbody>{rows}</tbody>\
        </table>"
    )
}

pub fn log_entry_html(ev: &WgEvent) -> String {
    match ev {
        WgEvent::Sent { inner_dst, peer, outer_dst } =>
            format!("<div class='log send'>→ SEND  inner={inner_dst}  peer={}  outer={outer_dst}</div>", peer.0),
        WgEvent::NoRoute { inner_dst } =>
            format!("<div class='log drop'>✗ DROP  inner={inner_dst}  (no route)</div>"),
        WgEvent::NoEndpoint { inner_dst, peer } =>
            format!("<div class='log drop'>✗ DROP  inner={inner_dst}  peer={}  (no endpoint)</div>", peer.0),
        WgEvent::Received { outer_src, peer, inner_src } =>
            format!("<div class='log recv'>← RECV  outer={outer_src}  peer={}  inner={inner_src}  ✓</div>", peer.0),
        WgEvent::Dropped { outer_src, peer, inner_src, reason } =>
            format!("<div class='log drop'>✗ DROP  outer={outer_src}  peer={}  inner={inner_src}  ({reason})</div>", peer.0),
        WgEvent::Roamed { peer, old_endpoint, new_endpoint } => {
            let old = old_endpoint.map(|e| e.to_string()).unwrap_or_else(|| "(none)".to_string());
            format!("<div class='log roam'>~ ROAM  peer={}  {old} → {new_endpoint}</div>", peer.0)
        }
    }
}

// Shared base styles used by both pages

fn base_styles() -> &'static str {
    r#"
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { background: #070b10; min-height: 100%; }
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; max-width: 960px; margin: 0 auto; min-height: 100vh; }
    header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 2rem; }
    h1 { color: #58a6ff; font-size: 1.4rem; margin-bottom: .25rem; }
    .meta { color: #8b949e; font-size: .85rem; }
    nav a { color: #8b949e; font-size: .85rem; text-decoration: none; white-space: nowrap; padding-top: .25rem; display: inline-block; border-bottom: 2px solid #8b949e; padding-bottom: .1rem; }
    nav a:hover { color: #58a6ff; border-bottom: 4px solid #58a6ff; }
    "#
}

// Full page (served on GET /)

pub fn full_page(iface: &Interface) -> String {
    let table = table_html(iface);
    let name = &iface.name;
    let addr = &iface.address;
    let port = iface.listen_port;
    let base = base_styles();

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WireGuard Viz — {name}</title>
  <style>
    {base}
    section {{ margin-bottom: 2rem; }}
    h2 {{ color: #79c0ff; font-size: .9rem; text-transform: uppercase;
          letter-spacing: .05em; border-bottom: 1px solid #30363d;
          padding-bottom: .4rem; margin-bottom: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
    th {{ text-align: left; color: #8b949e; font-weight: normal; padding: .4rem .75rem .4rem 0; font-size: .75rem; text-transform: uppercase; }}
    td {{ padding: .5rem .75rem .5rem 0; border-top: 1px solid #21262d; vertical-align: middle; }}
    .key  {{ color: #d2a8ff; }}
    .ip   {{ color: #7ee787; }}
    .ep   {{ color: #ffa657; }}
    .row-actions {{ display: flex; gap: .4rem; }}
    button {{ background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
              padding: .2rem .6rem; cursor: pointer; font-family: monospace; font-size: .8rem; }}
    button:hover {{ background: #388bfd22; border-color: #58a6ff; color: #58a6ff; }}
    .add-form {{ display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }}
    .add-form input {{ background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
                       padding: .25rem .5rem; font-family: monospace; font-size: .85rem; }}
    .add-form input[name=public_key]  {{ width: 18rem; }}
    .add-form input[name=allowed_ips] {{ width: 10rem; }}
    .add-form input[name=endpoint]    {{ width: 14rem; }}
    #event-log {{ max-height: 280px; overflow-y: auto; font-size: .85rem; }}
    .log {{ padding: .3rem 0; border-bottom: 1px solid #21262d; }}
    .log.send {{ color: #58a6ff; }}
    .log.recv {{ color: #7ee787; }}
    .log.drop {{ color: #f85149; }}
    .log.roam {{ color: #ffa657; }}
    .log-empty {{ color: #8b949e; font-style: italic; }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{name}</h1>
      <p class="meta">addr: {addr} &nbsp;·&nbsp; port: {port}</p>
    </div>
    <nav><a href="/about">What's this all about, then? →</a></nav>
  </header>

  <section>
    <h2>Cryptokey Routing Table</h2>
    <div id="routing-table">{table}</div>
  </section>

  <section>
    <h2>Add Peer</h2>
    <form class="add-form" action="/action/add_peer" method="post" data-ajax autocomplete="off">
      <input name="public_key"  placeholder="public key" required autocomplete="off" data-1p-ignore data-lpignore="true">
      <input name="allowed_ips" placeholder="10.0.0.x/32" required autocomplete="off" data-1p-ignore data-lpignore="true">
      <input name="endpoint"    placeholder="1.2.3.4:51820 (optional)"  autocomplete="off" data-1p-ignore data-lpignore="true">
      <button type="submit">Add</button>
    </form>
  </section>

  <section>
    <h2>Event Log</h2>
    <div id="event-log"><span class="log-empty">No events yet!</span></div>
  </section>

  <script>
    const es = new EventSource('/events');
    es.addEventListener('table', e => document.getElementById('routing-table').innerHTML = e.data);
    es.addEventListener('log',   e => {{
      const log = document.getElementById('event-log');
      log.querySelector('.log-empty')?.remove();
      log.insertAdjacentHTML('afterbegin', e.data);
    }});

    document.addEventListener('submit', e => {{
      if ('ajax' in e.target.dataset) {{
        e.preventDefault();
        fetch(e.target.action, {{
          method: 'POST',
          headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
          body: new URLSearchParams(new FormData(e.target)),
        }});
      }}
    }});
  </script>
</body>
</html>"#)
}

// About page (served on GET /about)

pub fn about_page() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>What's this all about, then?</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { background: #070b10; min-height: 100%; }
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; max-width: 960px; margin: 0 auto; min-height: 100vh; }
    header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 2.5rem; }
    h1 { color: #58a6ff; font-size: 1.4rem; line-height: 1.3; }
    nav a { color: #8b949e; font-size: .85rem; text-decoration: none; white-space: nowrap; padding-top: .25rem; display: inline-block; border-bottom: 2px solid #8b949e; padding-bottom: .1rem; }
    nav a:hover { color: #58a6ff; border-bottom: 4px solid #58a6ff; }
    article { line-height: 1.75; }
    h2 { color: #79c0ff; font-size: 1rem; margin: 2rem 0 .75rem; }
    p { margin-bottom: 1rem; color: #c9d1d9; }
    p:last-child { margin-bottom: 0; }
    code { background: #161b22; color: #7ee787; padding: .1em .35em; border: 1px solid #30363d; font-size: .9em; }
    .callout { background: #161b22; border-left: 3px solid #58a6ff; padding: .75rem 1rem; margin: 1.25rem 0; }
    .callout p { margin: 0; font-size: .9rem; color: #8b949e; }
    .callout p strong { color: #c9d1d9; }
    a { color: #58a6ff; }
    a:hover { text-decoration: underline; }
    nav a:hover { text-decoration: none; }
    .section-ref { color: #8b949e; font-size: .8rem; }
  </style>
</head>
<body>
  <header>
    <h1>What's this all about, then?</h1>
    <nav><a href="/">← back to the demo</a></nav>
  </header>

  <article>

    <h2>WireGuard in one paragraph</h2>
    <p>
      WireGuard is a modern VPN that lives inside the Linux kernel (and other OS kernels).
      It is deliberately minimal — the reference implementation is around 4,000 lines of code,
      compared to OpenVPN's ~400,000. That simplicity is a security feature: less code means
      a smaller attack surface and an implementation you can actually audit. WireGuard uses
      state-of-the-art cryptography (Curve25519 key exchange, ChaCha20-Poly1305 encryption,
      BLAKE2 hashing) and a handshake protocol called Noise_IKpsk2.
    </p>

    <h2>The core idea: route by identity, not address</h2>
    <p>
      Traditional VPNs route packets by IP address, with authentication bolted on top.
      WireGuard flips this. Every peer is identified by a <strong>Curve25519 public key</strong>,
      and routing decisions are made based on that cryptographic identity.
      The IP addresses a peer is allowed to claim are declared up front in the configuration
      — they can't be forged, because the keys can't be forged.
    </p>
    <p>
      This is the <strong>Cryptokey Routing Table</strong>: a mapping from public key to a set of
      allowed inner IP ranges (CIDRs). It is the foundational data structure of WireGuard,
      described in Section 2 of the whitepaper.
    </p>

    <div class="callout">
      <p><strong>Whitepaper reference:</strong> Jason A. Donenfeld, <a href="https://www.wireguard.com/papers/wireguard.pdf" target="_blank">"WireGuard: Next Generation
      Kernel Network Tunnel,"</a> NDSS 2017. Section 2 introduces Cryptokey Routing;
      Section 3 covers the send/receive flows in detail.</p>
    </div>

    <h2>The routing table: what the demo shows</h2>
    <p>
      In the demo, <code>wg0</code> is a WireGuard interface with an inner address of
      <code>10.0.0.1/24</code>. Each row in the table is a <em>peer</em>: a remote
      machine identified by its public key. Each peer has:
    </p>
    <p>
      &nbsp;&nbsp;<code>allowed_ips</code> — the inner IP addresses this peer is permitted to use.<br>
      &nbsp;&nbsp;<code>endpoint</code> — the real outer <code>IP:port</code> where packets for this peer are sent.
    </p>
    <p>
      The <code>allowed_ips</code> field serves double duty: it is used <em>outbound</em>
      to decide which peer to send a packet to (longest-prefix match, like a routing table),
      and <em>inbound</em> to validate that the decrypted packet's source IP is one the peer
      is actually authorized to use.
    </p>

    <h2>Sending a packet</h2>
    <p>
      When <code>wg0</code> needs to send a packet to an inner destination (say <code>10.0.0.2</code>),
      it walks the cryptokey routing table looking for a peer whose <code>allowed_ips</code>
      contains that address. Once found, it encrypts the entire IP packet using that peer's
      public key (via the Noise handshake session), wraps it in a new UDP packet addressed
      to the peer's outer <code>endpoint</code>, and sends it on its way.
    </p>
    <p>
      The inner packet — source address, destination address, payload — becomes completely
      opaque to anyone on the internet. Only the outer <code>IP:port</code> is visible.
      Hit <strong>Send</strong> on any row in the demo to see this lookup in action.
    </p>

    <h2>Receiving a packet</h2>
    <p>
      When a UDP packet arrives at <code>wg0</code>'s listen port, WireGuard identifies
      which peer's session key can decrypt it (the handshake establishes this association).
      After decryption, the inner source IP is revealed. WireGuard then checks: is this IP
      in that peer's <code>allowed_ips</code>? If not, the packet is silently dropped —
      even though it decrypted correctly. A peer can't claim an IP it wasn't configured for.
    </p>
    <p>
      This is the security guarantee: cryptographic identity and routing policy are unified.
      You cannot receive a packet that claims to come from <code>10.0.0.2</code> unless it
      was encrypted by the key associated with that address. Hit <strong>Recv</strong> in the
      demo to see a successful receive, and try adding a peer without an allowed IP that matches
      to observe the drop.
    </p>

    <h2>Endpoints &amp; Roaming</h2>
    <p>
      The <code>endpoint</code> field — the outer <code>IP:port</code> — is treated as
      <em>mutable hint</em>, not authoritative configuration. Every time WireGuard
      successfully decrypts and validates a packet from a peer, if that packet arrived from
      a different outer IP than the one on record, it silently updates the endpoint.
    </p>
    <p>
      No signaling, no reconnect, no re-authentication. A phone can move from WiFi to LTE,
      change its public IP entirely, and the tunnel just keeps working — the next valid
      packet updates the table. Hit <strong>Roam</strong> in the demo to watch the endpoint
      column update live as the "phone" moves to a new IP.
    </p>

    <h2>Why TailScale is built on this</h2>
    <p>
      TailScale is, at its core, WireGuard plus two things WireGuard deliberately leaves out:
      <strong>key distribution</strong> and <strong>NAT traversal</strong>.
    </p>
    <p>
      WireGuard assumes you have already exchanged public keys out-of-band and configured
      each peer's <code>allowed_ips</code>. TailScale's coordination server (hosted by
      TailScale, or self-hosted as Headscale) handles this automatically — when you add a
      device to your tailnet, it gets a public key, that key is distributed to all other
      devices, and each device's WireGuard cryptokey routing table is updated.
    </p>
    <p>
      NAT traversal (getting two devices behind separate home routers to talk directly)
      is handled via DERP relay servers and ICE-style hole-punching — again, completely
      transparent to WireGuard itself, which just sees packets arriving from (possibly
      changing) outer endpoints and updates its table accordingly.
    </p>
    <p>
      The elegant result: TailScale gives every device in your network a stable inner IP
      (<code>100.x.x.x</code> in the CGNAT range), backed by exactly the cryptokey routing
      model this demo illustrates.
    </p>

  </article>
</body>
</html>"#
}
