use crate::logging::{LevelFilter, get_recent_logs, get_ring_buffer_len, subscribe_logs};
use crate::services::observability::html::DASHBOARD_HTML;
use crate::services::observability::status::{
    LogsResponse, StatusResponse, collect_status_response,
};
use crate::services::utils::WanLeaseReceiver;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use futures_util::stream::BoxStream;
use futures_util::{Stream, StreamExt};
use log::{debug, warn};
use serde::Deserialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::sync::watch::Receiver as WatchReceiver;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::BroadcastStream;
use tower::limit::ConcurrencyLimitLayer;

pub const HTTP_PORT: u16 = 80;
pub const MAX_CONCURRENT_HTTP_CONNECTIONS: usize = 16;
pub const MAX_CONCURRENT_SSE_STREAMS: usize = 4;
pub const DEFAULT_LOG_LINES_COUNT: usize = 100;
pub const MAX_LOG_LINES_COUNT: usize = 500;

#[derive(Clone)]
pub struct AppState {
    pub lease_rx: WanLeaseReceiver,
    pub watchdog_active: bool,
    pub sse_semaphore: Arc<Semaphore>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFilterParam {
    Off,
    Error,
    #[serde(alias = "warning")]
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogFilterParam> for LevelFilter {
    fn from(param: LogFilterParam) -> Self {
        match param {
            LogFilterParam::Off => LevelFilter::Off,
            LogFilterParam::Error => LevelFilter::Error,
            LogFilterParam::Warn => LevelFilter::Warn,
            LogFilterParam::Info => LevelFilter::Info,
            LogFilterParam::Debug => LevelFilter::Debug,
            LogFilterParam::Trace => LevelFilter::Trace,
        }
    }
}

impl std::str::FromStr for LogFilterParam {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(()),
        }
    }
}

#[derive(Deserialize, Default)]
pub struct LogsQueryParams {
    pub lines: Option<usize>,
    pub level: Option<LogFilterParam>,
}

pub struct StreamPermitGuard<S> {
    inner: S,
    _permit: OwnedSemaphorePermit,
}

impl<S> StreamPermitGuard<S> {
    pub fn new(inner: S, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            _permit: permit,
        }
    }
}

impl<S: Stream + Unpin> Stream for StreamPermitGuard<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

pub struct HttpServer {
    listener: TcpListener,
    state: AppState,
}

impl HttpServer {
    pub fn new(listener: TcpListener, lease_rx: WanLeaseReceiver, watchdog_active: bool) -> Self {
        let state = AppState {
            lease_rx,
            watchdog_active,
            sse_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_SSE_STREAMS)),
        };
        Self { listener, state }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self, mut shutdown_rx: WatchReceiver<bool>) {
        let app = create_router(self.state);
        let serve = axum::serve(self.listener, app);
        let graceful = serve.with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        });

        if let Err(e) = graceful.await {
            warn!("[observability] HTTP server encountered an error: {e}");
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/api/status", get(handle_status))
        .route("/api/logs", get(handle_logs))
        .route("/api/logs/stream", get(handle_logs_stream))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_HTTP_CONNECTIONS))
        .with_state(state)
}

async fn handle_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn handle_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let wan_lease = state.lease_rx.borrow().clone();
    let status = collect_status_response(&wan_lease, state.watchdog_active);
    Json(status)
}

async fn handle_logs(Query(params): Query<LogsQueryParams>) -> Json<LogsResponse> {
    let lines_count = params
        .lines
        .unwrap_or(DEFAULT_LOG_LINES_COUNT)
        .min(MAX_LOG_LINES_COUNT);
    let level_filter = params.level.map(LevelFilter::from);
    let lines = get_recent_logs(lines_count, level_filter);
    let total_lines_available = get_ring_buffer_len();

    Json(LogsResponse {
        total_lines_available,
        lines,
    })
}

async fn handle_logs_stream(State(state): State<AppState>) -> Response {
    let permit = match state.sse_semaphore.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                "[observability] Max concurrent SSE streams ({}) reached. Rejecting stream request.",
                MAX_CONCURRENT_SSE_STREAMS
            );
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    };

    debug!("[observability] Client connected to SSE log stream");
    let log_rx = subscribe_logs();
    let stream: BoxStream<'static, Result<Event, Infallible>> =
        Box::pin(BroadcastStream::new(log_rx).filter_map(|res| async move {
            match res {
                Ok(line) => {
                    let clean = line.trim_end().to_string();
                    Some(Ok(Event::default().data(clean)))
                }
                Err(_) => None,
            }
        }));

    let guarded_stream = StreamPermitGuard::new(stream, permit);
    Sse::new(guarded_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::push_to_ring_buffer_and_broadcast;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::sync::watch;

    #[test]
    fn test_log_filter_param_from_str_and_conversion() {
        assert_eq!("error".parse::<LogFilterParam>(), Ok(LogFilterParam::Error));
        assert_eq!("WARN".parse::<LogFilterParam>(), Ok(LogFilterParam::Warn));
        assert_eq!(
            "warning".parse::<LogFilterParam>(),
            Ok(LogFilterParam::Warn)
        );
        assert_eq!("info".parse::<LogFilterParam>(), Ok(LogFilterParam::Info));
        assert_eq!("debug".parse::<LogFilterParam>(), Ok(LogFilterParam::Debug));
        assert_eq!("trace".parse::<LogFilterParam>(), Ok(LogFilterParam::Trace));
        assert_eq!("off".parse::<LogFilterParam>(), Ok(LogFilterParam::Off));
        assert!("invalid".parse::<LogFilterParam>().is_err());

        assert_eq!(LevelFilter::from(LogFilterParam::Error), LevelFilter::Error);
        assert_eq!(LevelFilter::from(LogFilterParam::Warn), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogFilterParam::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogFilterParam::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogFilterParam::Trace), LevelFilter::Trace);
        assert_eq!(LevelFilter::from(LogFilterParam::Off), LevelFilter::Off);
    }

    #[tokio::test]
    async fn test_http_server_endpoints() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_lease_tx, lease_rx) = watch::channel(crate::services::WanLease::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = HttpServer::new(listener, lease_rx, true);
        tokio::spawn(async move {
            server.run(shutdown_rx).await;
        });

        // 1. Test GET / (HTML Dashboard)
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(client);
        let mut first_line = String::new();
        reader.read_line(&mut first_line).await.unwrap();
        assert!(first_line.contains("200 OK"));

        // 2. Test GET /api/status (JSON)
        let mut client2 = TcpStream::connect(addr).await.unwrap();
        client2
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader2 = BufReader::new(client2);
        let mut status_line = String::new();
        reader2.read_line(&mut status_line).await.unwrap();
        assert!(status_line.contains("200 OK"));

        // 3. Test GET /api/logs (JSON)
        push_to_ring_buffer_and_broadcast("[2026-09-27T18:30:00Z] [INFO] [test] Test log entry\n");
        let mut client3 = TcpStream::connect(addr).await.unwrap();
        client3
            .write_all(b"GET /api/logs?lines=10&level=info HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader3 = BufReader::new(client3);
        let mut logs_line = String::new();
        reader3.read_line(&mut logs_line).await.unwrap();
        assert!(logs_line.contains("200 OK"));

        // 4. Test Method Not Allowed (POST /api/status)
        let mut client4 = TcpStream::connect(addr).await.unwrap();
        client4
            .write_all(b"POST /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader4 = BufReader::new(client4);
        let mut not_allowed_line = String::new();
        reader4.read_line(&mut not_allowed_line).await.unwrap();
        assert!(not_allowed_line.contains("405 Method Not Allowed"));

        // 5. Test Not Found (GET /nonexistent)
        let mut client5 = TcpStream::connect(addr).await.unwrap();
        client5
            .write_all(b"GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader5 = BufReader::new(client5);
        let mut not_found_line = String::new();
        reader5.read_line(&mut not_found_line).await.unwrap();
        assert!(not_found_line.contains("404 Not Found"));

        // Clean shutdown
        let _ = shutdown_tx.send(true);
    }
}
