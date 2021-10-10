use std::{net::IpAddr, time::Duration};

use fxhash::FxHashMap;
use tokio::{
    net::lookup_host,
    select,
    sync::{mpsc, oneshot, OnceCell},
    time::{sleep_until, Instant, Sleep},
};
use tracing::{error, info};

use crate::protocol::{BLACK_HOLE_LOCAL_ADDR, DNS_UPDATE_PERIOD_SEC};

type DNSTask = (Box<str>, oneshot::Sender<IpAddr>);
type DNSTx = mpsc::Sender<DNSTask>;
type DNSRx = mpsc::Receiver<DNSTask>;

pub static DNS_TX: OnceCell<DNSTx> = OnceCell::const_new();

pub fn start_dns_resolver_thread() {
    info!("starting dns resolver");
    let (dns_tx, dns_rx) = mpsc::channel(100);
    tokio::spawn(dns_resolver(dns_rx));
    let _ = DNS_TX
        .set(dns_tx)
        .map_err(|e| error!("failed to set DNS_TX: {:#}", e));
}

async fn dns_resolver(mut incoming_tasks: DNSRx) {
    let mut cache = FxHashMap::<Box<str>, (IpAddr, usize)>::default();
    let (update_cache_tx, mut update_cache_rx) = mpsc::channel(100);
    let mut timer = Timer::new();
    loop {
        select! {
            _ = timer.sleep() => {
                timer.update();
                timer.slower();
            }
            maybe_cache_update = update_cache_rx.recv() => {
                match maybe_cache_update {
                    Some((query, ip)) => {
                        cache.insert(query, (ip, timer.counter));
                    },
                    None => error!("unexpected None received when updating cache"),
                }
            }
            maybe_task = incoming_tasks.recv() => {
                timer.faster();
                match maybe_task {
                    None => {
                        info!("shutting down dns resolver");
                        return;
                    }
                    Some((addr, ret_tx)) => {
                        if let Some((ip, timestamp)) = cache.get(&addr) {
                            if timer.counter - timestamp < 2 {
                                let _ = ret_tx.send(*ip);
                                continue;
                            }
                        }
                        tokio::spawn(single_resolve_task(addr, ret_tx, update_cache_tx.clone()));
                    }
                }
            }
        }
    }
}

struct Timer {
    instant: Instant,
    counter: usize,
    slow: usize,
}

impl Timer {
    fn new() -> Self {
        Self {
            instant: Instant::now(),
            counter: 0,
            slow: 0,
        }
    }
    fn sleep(&self) -> Sleep {
        return sleep_until(
            self.instant
                + Duration::from_secs(if self.slow == 0 {
                    DNS_UPDATE_PERIOD_SEC * 20
                } else {
                    DNS_UPDATE_PERIOD_SEC
                }),
        );
    }

    fn update(&mut self) {
        self.counter += 1;
        self.instant = Instant::now();
    }

    fn slower(&mut self) {
        if self.slow > 0 {
            self.slow -= 1;
        }
    }

    fn faster(&mut self) {
        self.slow = 2;
    }
}

async fn single_resolve_task(
    query: Box<str>,
    ret_tx: oneshot::Sender<IpAddr>,
    update_cache_tx: mpsc::Sender<(Box<str>, IpAddr)>,
) {
    let res = match lookup_host((&*query, 0)).await {
        Ok(mut iter) => match iter.next() {
            Some(res) => res.ip(),
            None => {
                error!("failed to lookup host: the result is empty");
                BLACK_HOLE_LOCAL_ADDR.into()
            }
        },
        Err(e) => {
            error!("failed to lookup host: {:#}", e);
            BLACK_HOLE_LOCAL_ADDR.into()
        }
    };
    let _ = ret_tx.send(res);
    let _ = update_cache_tx.send((query, res)).await;
}
