//! Prometheus metrics, served on a separate internal port (never through the
//! public listener or Caddy).
//!
//! Dependency-free on purpose: a handful of counters and one latency
//! histogram per route, rendered in the Prometheus text format.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};

/// Latency histogram bucket bounds, in seconds.
const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

#[derive(Default)]
struct Histogram {
    buckets: [u64; BUCKETS.len()],
    sum: f64,
    count: u64,
}

#[derive(Default)]
struct Inner {
    /// (method, route, status) → count
    requests: BTreeMap<(String, String, u16), u64>,
    /// (method, route) → latency
    latency: BTreeMap<(String, String), Histogram>,
}

/// Shared metrics registry. Cheap to clone.
#[derive(Clone, Default)]
pub struct Metrics(Arc<Mutex<Inner>>);

impl Metrics {
    fn record(&self, method: &str, route: &str, status: u16, seconds: f64) {
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *inner
            .requests
            .entry((method.to_string(), route.to_string(), status))
            .or_default() += 1;
        let h = inner
            .latency
            .entry((method.to_string(), route.to_string()))
            .or_default();
        for (i, bound) in BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                h.buckets[i] += 1;
            }
        }
        h.sum += seconds;
        h.count += 1;
    }

    /// The Prometheus text exposition of everything recorded so far.
    pub fn render(&self) -> String {
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();
        out.push_str(
            "# HELP brigid_http_requests_total HTTP requests by method, route and status.\n",
        );
        out.push_str("# TYPE brigid_http_requests_total counter\n");
        for ((method, route, status), n) in &inner.requests {
            let _ = writeln!(
                out,
                "brigid_http_requests_total{{method=\"{method}\",route=\"{route}\",status=\"{status}\"}} {n}"
            );
        }
        out.push_str(
            "# HELP brigid_http_request_duration_seconds HTTP request latency by method and route.\n",
        );
        out.push_str("# TYPE brigid_http_request_duration_seconds histogram\n");
        for ((method, route), h) in &inner.latency {
            let labels = format!("method=\"{method}\",route=\"{route}\"");
            for (bound, n) in BUCKETS.iter().zip(h.buckets) {
                let _ = writeln!(
                    out,
                    "brigid_http_request_duration_seconds_bucket{{{labels},le=\"{bound}\"}} {n}"
                );
            }
            let _ = writeln!(
                out,
                "brigid_http_request_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}",
                h.count
            );
            let _ = writeln!(
                out,
                "brigid_http_request_duration_seconds_sum{{{labels}}} {}",
                h.sum
            );
            let _ = writeln!(
                out,
                "brigid_http_request_duration_seconds_count{{{labels}}} {}",
                h.count
            );
        }
        out
    }
}

/// Route label: the matched route pattern (`/auth/passkeys/{id}`, never the
/// raw path, so ids and usernames never become labels), or `static` for the
/// UI fallback.
async fn track(State(metrics): State<Metrics>, req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "static".to_string(), |p| p.as_str().to_string());
    let start = Instant::now();
    let response = next.run(req).await;
    metrics.record(
        &method,
        &route,
        response.status().as_u16(),
        start.elapsed().as_secs_f64(),
    );
    response
}

/// Wrap `router` so every request is counted in `metrics`.
pub fn instrument(router: Router, metrics: Metrics) -> Router {
    router.layer(middleware::from_fn_with_state(metrics, track))
}

/// The router of the internal metrics listener: `GET /metrics`.
pub fn metrics_router(metrics: Metrics) -> Router {
    Router::new().route(
        "/metrics",
        get(|State(m): State<Metrics>| async move {
            ([("content-type", "text/plain; version=0.0.4")], m.render()).into_response()
        })
        .with_state(metrics),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_counts_and_buckets() {
        let m = Metrics::default();
        m.record("GET", "/health", 200, 0.003);
        m.record("GET", "/health", 200, 0.2);
        m.record("POST", "/auth/login/begin", 404, 0.01);
        let text = m.render();
        assert!(text.contains(
            "brigid_http_requests_total{method=\"GET\",route=\"/health\",status=\"200\"} 2"
        ));
        assert!(text.contains(
            "brigid_http_request_duration_seconds_bucket{method=\"GET\",route=\"/health\",le=\"0.005\"} 1"
        ));
        assert!(text.contains(
            "brigid_http_request_duration_seconds_bucket{method=\"GET\",route=\"/health\",le=\"+Inf\"} 2"
        ));
        assert!(text.contains("status=\"404\""));
    }
}
