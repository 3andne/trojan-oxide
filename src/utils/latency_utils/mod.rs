use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use tokio::{
    net::TcpStream,
    time::{sleep, Instant},
};
use tracing::info;

pub static LATENCY_EST: AtomicU32 = AtomicU32::new(100);

const SAMPLE_WEBSITES: [&'static str; 17] = [
    "www.google.com",
    "www.youtube.com",
    "www.stackoverflow.com",
    "www.github.com",
    "www.facebook.com",
    "www.twitter.com",
    "www.instagram.com",
    "www.wikipedia.org",
    "www.xvideos.com",
    "www.whatsapp.com",
    "www.pornhub.com",
    "www.amazon.com",
    "www.live.com",
    "www.reddit.com",
    "www.microsoftonline.com",
    "www.zoom.us",
    "www.weather.com",
];

pub fn start_latency_estimator() {
    info!("starting latency_estimator");
    tokio::spawn(latency_estimator_service());
}

async fn latency_estimator_service() {
    loop {
        let mut elapsed = 0;
        let mut accessed = 0;
        for w in SAMPLE_WEBSITES {
            let start = Instant::now();
            if let Ok(_conn) = TcpStream::connect(w).await {
                elapsed += start.elapsed().as_millis() as u32;
                accessed += 1;
            }
        }
        let new = if accessed == 0 {
            100
        } else {
            elapsed / accessed
        };
        info!("new est latency {}", new);
        let curr = LATENCY_EST.load(Ordering::Acquire);
        LATENCY_EST.store((new + curr) / 2, Ordering::Release);

        sleep(Duration::from_secs(5 * 60)).await;
    }
}
