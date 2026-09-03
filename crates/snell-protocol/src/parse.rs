/// Incremental parse: `Need(total)` is the buffer length required to try again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseState<T> {
    Need(usize),
    Done(T),
}
