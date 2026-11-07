//! Explicit Windows file picker. Paths never come from the WebView.
use crate::{Error, Result};
use std::{
    ffi::OsString,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    CommDlgExtendedError, GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST,
    OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
pub fn choose(save: bool, owner: isize) -> Result<Option<PathBuf>> {
    let wide = |text: &str| std::ffi::OsStr::new(text).encode_wide().collect::<Vec<_>>();
    let filter = wide("Копия КотоПизделки (*.kotobackup)\0*.kotobackup\0\0");
    let title = wide(if save {
        "Сохранить резервную копию\0"
    } else {
        "Восстановить резервную копию\0"
    });
    let extension = wide("kotobackup\0");
    let mut filename = vec![0u16; 32768];
    if save {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::LocalIo)?
            .as_secs();
        let initial = wide(&format!("KotoPizdelka-profile-{now}.kotobackup"));
        filename[..initial.len()].copy_from_slice(&initial);
    }
    // All borrowed UTF-16 buffers live through the modal Win32 call.
    let mut data: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    data.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    data.hwndOwner = owner as _;
    data.lpstrFilter = filter.as_ptr();
    data.lpstrTitle = title.as_ptr();
    data.lpstrDefExt = extension.as_ptr();
    data.lpstrFile = filename.as_mut_ptr();
    data.nMaxFile = filename.len() as u32;
    data.Flags = OFN_EXPLORER
        | OFN_NOCHANGEDIR
        | OFN_PATHMUSTEXIST
        | if save { 0 } else { OFN_FILEMUSTEXIST };
    let result = unsafe {
        if save {
            GetSaveFileNameW(&mut data)
        } else {
            GetOpenFileNameW(&mut data)
        }
    };
    if result == 0 {
        return if unsafe { CommDlgExtendedError() } == 0 {
            Ok(None)
        } else {
            Err(Error::LocalIo)
        };
    }
    let len = filename
        .iter()
        .position(|c| *c == 0)
        .ok_or(Error::LocalIo)?;
    Ok(Some(OsString::from_wide(&filename[..len]).into()))
}
