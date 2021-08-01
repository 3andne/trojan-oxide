
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

#[macro_export]
macro_rules! expect_buf_len {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Err(ParserError::Incomplete(stringify!($len)));
        }
    };
    ($buf:expr, $len:expr, $mark:expr) => {
        if $buf.len() < $len {
            // debug!("expect_buf_len {}", $mark);
            return Err(ParserError::Incomplete($mark.into()));
        }
    };
}