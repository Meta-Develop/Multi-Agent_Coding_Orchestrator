pub(crate) fn skip_current() -> std::io::Result<bool> {
    let current = std::thread::current();
    match current.name() {
        Some(name) => crate::containment_probe::skip_if_unavailable(name),
        None => Ok(false),
    }
}

macro_rules! skip_without_containment {
    () => {
        if $crate::test_containment::skip_current().expect("probe containment capability") {
            return;
        }
    };
    (ok) => {
        if $crate::test_containment::skip_current()? {
            return ::std::result::Result::Ok(());
        }
    };
}
