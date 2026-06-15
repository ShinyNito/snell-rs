use tokio::sync::watch;
use tokio::time::{Duration, Instant, sleep_until};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RelayActivityTimeouts {
    pub(crate) initial: Duration,
    pub(crate) idle: Duration,
}

impl RelayActivityTimeouts {
    pub(crate) const fn new(initial: Duration, idle: Duration) -> Self {
        Self { initial, idle }
    }
}

#[derive(Clone)]
pub(crate) struct RelayActivity {
    last_activity: watch::Sender<Instant>,
}

impl RelayActivity {
    pub(crate) fn new() -> (Self, watch::Receiver<Instant>) {
        let (last_activity, receiver) = watch::channel(Instant::now());
        (Self { last_activity }, receiver)
    }

    pub(crate) fn record(&self) {
        let _ = self.last_activity.send(Instant::now());
    }
}

pub(crate) async fn wait_relay_idle(
    mut last_activity: watch::Receiver<Instant>,
    timeouts: RelayActivityTimeouts,
) {
    let mut deadline = *last_activity.borrow_and_update() + timeouts.initial;
    let idle = sleep_until(deadline);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            () = &mut idle => return,
            changed = last_activity.changed() => {
                if changed.is_err() {
                    return;
                }
                deadline = *last_activity.borrow_and_update() + timeouts.idle;
                idle.as_mut().reset(deadline);
            }
        }
    }
}
