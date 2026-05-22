mod events;
mod interface;
mod net;
mod render;
mod types;

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU8, Ordering};

use axum::{
    Router,
    extract::{Form, State},
    response::{Html, sse::{Event, KeepAlive, Sse}},
    routing::{get, post},
};
use async_stream::stream;
use serde::Deserialize;
use tokio::sync::broadcast;

use interface::Interface;
use types::{PrivateKey, PublicKey};

// App state

#[derive(Clone)]
struct SsePush {
    table_html: String,
    log_html: String,
}

#[derive(Clone)]
struct AppState {
    iface: Arc<Mutex<Interface>>,
    tx: broadcast::Sender<SsePush>,
    roam_counter: Arc<AtomicU8>,
}

impl AppState {
    fn push(&self, events: Vec<crate::events::WgEvent>) {
        let table_html = render::table_html(&self.iface.lock().unwrap());
        let log_html: String = events.iter().map(render::log_entry_html).collect();
        let _ = self.tx.send(SsePush { table_html, log_html });
    }

    fn push_one(&self, ev: crate::events::WgEvent) {
        self.push(vec![ev]);
    }
}

// Form types

#[derive(Deserialize)]
struct PeerKeyForm {
    peer_key: String,
}

#[derive(Deserialize)]
struct AddPeerForm {
    public_key: String,
    allowed_ips: String,
    #[serde(default)]
    endpoint: Option<String>,
}

// Handlers

async fn index(State(s): State<AppState>) -> Html<String> {
    Html(render::full_page(&s.iface.lock().unwrap()))
}

async fn about() -> Html<&'static str> {
    Html(render::about_page())
}

async fn sse_events(State(s): State<AppState>) -> impl axum::response::IntoResponse {
    let mut rx = s.tx.subscribe();
    let initial = render::table_html(&s.iface.lock().unwrap());

    type StreamItem = Result<Event, axum::Error>;
    Sse::new(stream! {
        // Send current table immediately so a fresh client isn't blank.
        yield StreamItem::Ok(Event::default().event("table").data(initial));
        loop {
            match rx.recv().await {
                Ok(push) => {
                    yield StreamItem::Ok(Event::default().event("table").data(push.table_html));
                    if !push.log_html.is_empty() {
                        yield StreamItem::Ok(Event::default().event("log").data(push.log_html));
                    }
                }
                Err(_) => break,
            }
        }
    })
    .keep_alive(KeepAlive::default())
}

async fn action_send(State(s): State<AppState>, Form(f): Form<PeerKeyForm>) {
    let ev = s.iface.lock().unwrap().simulate_send(&f.peer_key);
    s.push_one(ev);
}

async fn action_recv(State(s): State<AppState>, Form(f): Form<PeerKeyForm>) {
    let evs = s.iface.lock().unwrap().simulate_recv(&f.peer_key);
    s.push(evs);
}

async fn action_roam(State(s): State<AppState>, Form(f): Form<PeerKeyForm>) {
    let counter = s.roam_counter.fetch_add(1, Ordering::Relaxed);
    let evs = s.iface.lock().unwrap().simulate_roam(&f.peer_key, counter.wrapping_add(1));
    s.push(evs);
}

async fn action_add_peer(State(s): State<AppState>, Form(f): Form<AddPeerForm>) {
    let Ok(allowed_ips) = f.allowed_ips.parse() else { return };
    let endpoint = f.endpoint
        .filter(|e| !e.trim().is_empty())
        .and_then(|e| e.parse().ok());
    s.iface.lock().unwrap().add_peer(
        PublicKey::new(&f.public_key),
        vec![allowed_ips],
        endpoint,
    );
    s.push(vec![]);  // no log entry, just refresh the table
}

// Entry point

#[tokio::main]
async fn main() {
    let mut iface = Interface::new(
        "wg0",
        PrivateKey::new("server-private-key"),
        51820,
        "10.0.0.1/24".parse().unwrap(),
    );

    iface.add_peer(
        PublicKey::new("peer-a-public-key"),
        vec!["10.0.0.2/32".parse().unwrap()],
        Some("203.0.113.10:51820".parse().unwrap()),
    );
    iface.add_peer(
        PublicKey::new("peer-b-public-key"),
        vec!["10.0.0.3/32".parse().unwrap()],
        Some("198.51.100.7:51820".parse().unwrap()),
    );

    let (tx, _) = broadcast::channel(32);
    let state = AppState {
        iface: Arc::new(Mutex::new(iface)),
        tx,
        roam_counter: Arc::new(AtomicU8::new(1)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/about", get(about))
        .route("/events", get(sse_events))
        .route("/action/send", post(action_send))
        .route("/action/recv", post(action_recv))
        .route("/action/roam", post(action_roam))
        .route("/action/add_peer", post(action_add_peer))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    println!("Listening on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}
