#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // every OS variant is part of the fail-closed contract and is constructed on its host or in tests
enum RequiredContainmentPlatform {
    Linux,
    MacOs,
    Windows,
    OtherUnix,
    Other,
}

impl RequiredContainmentPlatform {
    const fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOs
        }
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
        {
            Self::OtherUnix
        }
        #[cfg(not(any(unix, target_os = "windows")))]
        {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewedRequiredContainmentBackend {
    LinuxSystemdCgroupV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // mismatch is retained for non-Linux hosts that cannot execute the reviewed Linux backend
enum RequiredContainmentRefusal {
    MacOsHasNoReviewedProfile,
    WindowsHasNoReviewedProfile,
    OtherUnixHasNoReviewedProfile,
    PlatformHasNoReviewedProfile,
    ReviewedBackendPlatformMismatch,
}

impl fmt::Display for RequiredContainmentRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MacOsHasNoReviewedProfile => {
                "macOS writable-runtime admission refused before spawn: no reviewed bounded side-effect containment profile exists; a Unix process group or worktree isolation is not verified side-effect confinement"
            }
            Self::WindowsHasNoReviewedProfile => {
                "Windows writable-runtime admission refused before spawn: no reviewed bounded side-effect containment profile exists; a Job Object alone or worktree isolation is not verified side-effect confinement"
            }
            Self::OtherUnixHasNoReviewedProfile => {
                "writable-runtime admission refused before spawn on this Unix platform: no reviewed bounded side-effect containment profile exists; a process group or worktree isolation is not verified side-effect confinement"
            }
            Self::PlatformHasNoReviewedProfile => {
                "writable-runtime admission refused before spawn on this platform: no reviewed bounded side-effect containment profile exists; direct-child ownership or worktree isolation is not verified side-effect confinement"
            }
            Self::ReviewedBackendPlatformMismatch => {
                "writable-runtime admission refused before spawn: the reviewed Linux systemd/cgroup v2 backend was selected on a non-Linux host"
            }
        })
    }
}

impl std::error::Error for RequiredContainmentRefusal {}

impl RequiredContainmentRefusal {
    fn into_io_error(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Unsupported, self)
    }
}

const fn classify_required_containment_backend(
    platform: RequiredContainmentPlatform,
) -> Result<ReviewedRequiredContainmentBackend, RequiredContainmentRefusal> {
    match platform {
        RequiredContainmentPlatform::Linux => {
            Ok(ReviewedRequiredContainmentBackend::LinuxSystemdCgroupV2)
        }
        RequiredContainmentPlatform::MacOs => {
            Err(RequiredContainmentRefusal::MacOsHasNoReviewedProfile)
        }
        RequiredContainmentPlatform::Windows => {
            Err(RequiredContainmentRefusal::WindowsHasNoReviewedProfile)
        }
        RequiredContainmentPlatform::OtherUnix => {
            Err(RequiredContainmentRefusal::OtherUnixHasNoReviewedProfile)
        }
        RequiredContainmentPlatform::Other => {
            Err(RequiredContainmentRefusal::PlatformHasNoReviewedProfile)
        }
    }
}

fn select_required_containment_backend(
    platform: RequiredContainmentPlatform,
    label: &str,
    command: &str,
) -> Result<ReviewedRequiredContainmentBackend, ProcessRunError> {
    classify_required_containment_backend(platform).map_err(|refusal| {
        ProcessRunError::ContainmentUnavailable {
            label: label.to_string(),
            command: command.to_string(),
            source: refusal.into_io_error(),
        }
    })
}
