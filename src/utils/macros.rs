
#[macro_export]
macro_rules! try_recv {
    ($T:tt, $instance:expr) => {
        try_recv!($T, $instance, break)
    };
    ($T:tt, $instance:expr, $then_expr:expr) => {
        match $instance.try_recv() {
            Err($T::error::TryRecvError::Empty) => (),
            _ => {
                tracing::info!("{} received", stringify!($instance));
                $then_expr;
            }
        }
    };
}

#[macro_export]
macro_rules! or_continue {
    ($res:expr) => {
        match $res {
            Ok(res) => res,
            Err(e) => {
                info!("{} failed due to {:?}", stringify!($res), e);
                continue;
            }
        }
    };
}