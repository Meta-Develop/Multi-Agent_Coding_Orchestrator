pub(crate) mod containment;

macro_rules! require_containment {
    ($test_name:literal) => {
        if $crate::support::containment::skip_if_unavailable($test_name)? {
            return Ok(());
        }
    };
}

pub(crate) use require_containment;
