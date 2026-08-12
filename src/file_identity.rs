#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowsFileIdentity {
    pub(crate) device: u64,
    pub(crate) file: u64,
}

impl WindowsFileIdentity {
    pub(crate) const fn from_parts(
        volume_serial_number: u32,
        file_index_high: u32,
        file_index_low: u32,
    ) -> Self {
        Self {
            device: volume_serial_number as u64,
            file: ((file_index_high as u64) << 32) | file_index_low as u64,
        }
    }
}

#[cfg(windows)]
pub(crate) fn windows_file_identity(file: &std::fs::File) -> std::io::Result<WindowsFileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live handle for the duration of the call and `information`
    // points to writable storage of the exact structure required by the API.
    let succeeded = unsafe {
        GetFileInformationByHandle(file.as_raw_handle(), std::ptr::from_mut(&mut information))
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(WindowsFileIdentity::from_parts(
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    ))
}

#[cfg(windows)]
pub(crate) struct WindowsPathIdentity {
    _file: std::fs::File,
    pub(crate) metadata: std::fs::Metadata,
    pub(crate) identity: WindowsFileIdentity,
}

#[cfg(windows)]
pub(crate) fn open_windows_path_identity(
    path: &std::path::Path,
) -> std::io::Result<WindowsPathIdentity> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    let identity = windows_file_identity(&file)?;
    Ok(WindowsPathIdentity {
        _file: file,
        metadata,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::WindowsFileIdentity;

    #[test]
    fn windows_file_identity_combines_both_file_index_halves() {
        let identity = WindowsFileIdentity::from_parts(0x89ab_cdef, 0x0123_4567, 0x7654_3210);

        assert_eq!(identity.device, 0x89ab_cdef);
        assert_eq!(identity.file, 0x0123_4567_7654_3210);
    }

    #[test]
    fn windows_file_identity_requires_matching_volume_and_file_index() {
        let expected = WindowsFileIdentity::from_parts(7, 11, 13);

        assert_eq!(expected, WindowsFileIdentity::from_parts(7, 11, 13));
        assert_ne!(expected, WindowsFileIdentity::from_parts(8, 11, 13));
        assert_ne!(expected, WindowsFileIdentity::from_parts(7, 12, 13));
        assert_ne!(expected, WindowsFileIdentity::from_parts(7, 11, 14));
    }
}
