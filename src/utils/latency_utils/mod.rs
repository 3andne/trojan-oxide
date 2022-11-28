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
    "www.google.com:443",
    "www.youtube.com:443",
    "www.stackoverflow.com:443",
    "www.github.com:443",
    "www.facebook.com:443",
    "www.twitter.com:443",
    "www.instagram.com:443",
    "www.wikipedia.org:443",
    "www.xvideos.com:443",
    "www.whatsapp.com:443",
    "www.pornhub.com:443",
    "www.amazon.com:443",
    "www.live.com:443",
    "www.reddit.com:443",
    "www.microsoftonline.com:80",
    "www.zoom.us:443",
    "www.weather.com:443",
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
            match TcpStream::connect(w).await {
                Ok(_conn) => {
                    elapsed += start.elapsed().as_millis() as u32;
                    accessed += 1;
                }
                Err(e) => {
                    info!("{} failed with {}", w, e);
                }
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
