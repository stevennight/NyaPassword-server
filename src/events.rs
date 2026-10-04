//! `GET /v1/events?token=<access token>`: a WebSocket that tells clients to
//! sync. Messages are [`npw_api::Event`] JSON; clients also poll every few
//! minutes, so a dropped connection only delays a sync.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use crate::auth::authenticate;
use crate::error::AppResult;
use crate::state::Shared;

#[derive(Deserialize)]
pub struct EventsQuery {
    token: String,
}

pub async fn events(State(st): State<Shared>, Query(q): Query<EventsQuery>, ws: WebSocketUpgrade) -> AppResult<Response> {
    let user = authenticate(&st, &q.token).await?;
    Ok(ws.on_upgrade(move |socket| run(st, user.account_id, user.device_id, socket)))
}

async fn run(st: Shared, account_id: String, device_id: String, mut socket: WebSocket) {
    let mut rx = st.events.subscribe();
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok((acct, event)) if acct == account_id => {
                    if let npw_api::Event::DeviceRevoked { device_id: d } = &event {
                        if *d == device_id {
                            let _ = socket.send(Message::Text(serde_json::to_string(&event).unwrap_or_default().into())).await;
                            break;
                        }
                    }
                    if socket.send(Message::Text(serde_json::to_string(&event).unwrap_or_default().into())).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // missed some: tell the client to sync everything
                    let e = npw_api::Event::AccountChanged;
                    if socket.send(Message::Text(serde_json::to_string(&e).unwrap_or_default().into())).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            _ = ping.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
        }
    }
}
