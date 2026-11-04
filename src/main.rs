#![cfg_attr(not(test), windows_subsystem = "windows")]
//! Local OTP: an offline Windows TOTP generator. Registered secrets are bound
//! to this PC's TPM and can never be displayed or exported again; the user
//! keeps the original secrets somewhere else.
mod otp;
mod vault;

use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    fs::{self, OpenOptions},
    io::{Read, Write},
    mem::zeroed,
    ops::Deref,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type H = *mut c_void;
type WndProc = unsafe extern "system" fn(H, u32, usize, isize) -> isize;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Point {
    x: i32,
    y: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}
#[repr(C)]
struct Msg {
    hwnd: H,
    message: u32,
    wparam: usize,
    lparam: isize,
    time: u32,
    pt: Point,
    private: u32,
}
#[repr(C)]
struct WndClass {
    style: u32,
    proc: Option<WndProc>,
    cls_extra: i32,
    wnd_extra: i32,
    instance: H,
    icon: H,
    cursor: H,
    background: H,
    menu: *const u16,
    name: *const u16,
}
#[repr(C)]
struct DrawItem {
    ctl_type: u32,
    ctl_id: u32,
    item_id: u32,
    action: u32,
    state: u32,
    item: H,
    dc: H,
    rc: Rect,
    data: usize,
}
#[repr(C)]
struct MeasureItem {
    ctl_type: u32,
    ctl_id: u32,
    item_id: u32,
    width: u32,
    height: u32,
    data: usize,
}
#[repr(C)]
struct MinMaxInfo {
    reserved: Point,
    max_size: Point,
    max_position: Point,
    min_track: Point,
    max_track: Point,
}
#[repr(C)]
struct InitCommonControls {
    size: u32,
    classes: u32,
}

#[link(name = "user32")]
unsafe extern "system" {
    fn RegisterClassW(w: *const WndClass) -> u16;
    fn CreateWindowExW(
        ex: u32,
        class: *const u16,
        name: *const u16,
        style: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        parent: H,
        menu: H,
        instance: H,
        param: H,
    ) -> H;
    fn DefWindowProcW(h: H, m: u32, w: usize, l: isize) -> isize;
    fn ShowWindow(h: H, n: i32) -> i32;
    fn UpdateWindow(h: H) -> i32;
    fn GetMessageW(m: *mut Msg, h: H, a: u32, b: u32) -> i32;
    fn PeekMessageW(m: *mut Msg, h: H, a: u32, b: u32, remove: u32) -> i32;
    fn TranslateMessage(m: *const Msg) -> i32;
    fn DispatchMessageW(m: *const Msg) -> isize;
    fn IsDialogMessageW(h: H, m: *mut Msg) -> i32;
    fn PostQuitMessage(code: i32);
    fn PostMessageW(h: H, m: u32, w: usize, l: isize) -> i32;
    fn MessageBoxW(h: H, text: *const u16, title: *const u16, flags: u32) -> i32;
    fn SetWindowTextW(h: H, t: *const u16) -> i32;
    fn EnableWindow(h: H, enabled: i32) -> i32;
    fn IsWindowEnabled(h: H) -> i32;
    fn IsWindowVisible(h: H) -> i32;
    fn GetWindowTextLengthW(h: H) -> i32;
    fn GetWindowTextW(h: H, t: *mut u16, n: i32) -> i32;
    fn SendMessageW(h: H, m: u32, w: usize, l: isize) -> isize;
    fn SetWindowLongPtrW(h: H, i: i32, v: isize) -> isize;
    fn GetWindowLongPtrW(h: H, i: i32) -> isize;
    fn SetTimer(h: H, id: usize, ms: u32, cb: H) -> usize;
    fn KillTimer(h: H, id: usize) -> i32;
    fn LoadCursorW(instance: H, name: *const u16) -> H;
    fn LoadIconW(instance: H, name: *const u16) -> H;
    fn SetCursor(cursor: H) -> H;
    fn GetClientRect(h: H, r: *mut Rect) -> i32;
    fn GetWindowRect(h: H, r: *mut Rect) -> i32;
    fn MoveWindow(h: H, x: i32, y: i32, w: i32, height: i32, repaint: i32) -> i32;
    fn SetWindowPos(h: H, after: H, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> i32;
    fn GetWindow(h: H, cmd: u32) -> H;
    fn InvalidateRect(h: H, r: *const Rect, erase: i32) -> i32;
    fn FillRect(dc: H, r: *const Rect, brush: H) -> i32;
    fn DrawTextW(dc: H, text: *const u16, n: i32, r: *mut Rect, format: u32) -> i32;
    fn GetDlgCtrlID(h: H) -> i32;
    fn GetDlgItem(h: H, id: i32) -> H;
    fn SetFocus(h: H) -> H;
    fn GetFocus() -> H;
    fn GetForegroundWindow() -> H;
    fn SetForegroundWindow(h: H) -> i32;
    fn IsChild(parent: H, h: H) -> i32;
    fn IsIconic(h: H) -> i32;
    fn GetKeyState(key: i32) -> i16;
    fn FindWindowW(class: *const u16, name: *const u16) -> H;
    fn GetDpiForWindow(h: H) -> u32;
    fn GetDpiForSystem() -> u32;
    fn SetWindowDisplayAffinity(h: H, affinity: u32) -> i32;
    fn DialogBoxIndirectParamW(
        instance: H,
        template: *const c_void,
        owner: H,
        proc: Option<WndProc>,
        param: isize,
    ) -> isize;
    fn EndDialog(h: H, result: isize) -> i32;
    fn GetSysColorBrush(index: i32) -> H;
    fn OpenClipboard(owner: H) -> i32;
    fn CloseClipboard() -> i32;
    fn EmptyClipboard() -> i32;
    fn SetClipboardData(format: u32, data: H) -> H;
    fn GetClipboardSequenceNumber() -> u32;
    fn RegisterClipboardFormatW(name: *const u16) -> u32;
}
#[link(name = "gdi32")]
unsafe extern "system" {
    fn GetStockObject(index: i32) -> H;
    fn CreateFontW(
        height: i32,
        width: i32,
        escapement: i32,
        orientation: i32,
        weight: i32,
        italic: u32,
        underline: u32,
        strike_out: u32,
        charset: u32,
        out_precision: u32,
        clip_precision: u32,
        quality: u32,
        pitch_and_family: u32,
        face: *const u16,
    ) -> H;
    fn DeleteObject(object: H) -> i32;
    fn SelectObject(dc: H, object: H) -> H;
    fn SetTextColor(dc: H, color: u32) -> u32;
    fn SetBkMode(dc: H, mode: i32) -> i32;
    fn CreateSolidBrush(color: u32) -> H;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> H;
    fn MoveFileExW(old: *const u16, new: *const u16, flags: u32) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        sharing: u32,
        security: H,
        creation: u32,
        flags: u32,
        template: H,
    ) -> H;
    fn CloseHandle(handle: H) -> i32;
    fn CreateMutexW(attributes: H, initial_owner: i32, name: *const u16) -> H;
    fn GetLastError() -> u32;
    fn GlobalAlloc(flags: u32, bytes: usize) -> H;
    fn GlobalLock(memory: H) -> *mut c_void;
    fn GlobalUnlock(memory: H) -> i32;
    fn GlobalFree(memory: H) -> H;
    fn MulDiv(number: i32, numerator: i32, denominator: i32) -> i32;
    fn Sleep(ms: u32);
}
#[link(name = "comctl32")]
unsafe extern "system" {
    fn InitCommonControlsEx(init: *const InitCommonControls) -> i32;
}
#[link(name = "wtsapi32")]
unsafe extern "system" {
    fn WTSRegisterSessionNotification(window: H, flags: u32) -> i32;
    fn WTSUnRegisterSessionNotification(window: H) -> i32;
}

const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_SIZE: u32 = 0x0005;
const WM_ACTIVATE: u32 = 0x0006;
const WM_SETFOCUS: u32 = 0x0007;
const WM_ENDSESSION: u32 = 0x0016;
const WM_GETMINMAXINFO: u32 = 0x0024;
const WM_DRAWITEM: u32 = 0x002B;
const WM_MEASUREITEM: u32 = 0x002C;
const WM_SETFONT: u32 = 0x0030;
const WM_KEYDOWN: u32 = 0x0100;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_INITDIALOG: u32 = 0x0110;
const WM_COMMAND: u32 = 0x0111;
const WM_TIMER: u32 = 0x0113;
const WM_CTLCOLORSTATIC: u32 = 0x0138;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_POWERBROADCAST: u32 = 0x0218;
const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
const WM_DPICHANGED: u32 = 0x02E0;
const PBT_APMSUSPEND: usize = 4;
const WTS_CONSOLE_DISCONNECT: usize = 2;
const WTS_REMOTE_DISCONNECT: usize = 4;
const WTS_SESSION_LOGOFF: usize = 6;
const WTS_SESSION_LOCK: usize = 7;

const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
const WS_POPUP: u32 = 0x8000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CAPTION: u32 = 0x00C0_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const WS_BORDER: u32 = 0x0080_0000;
const WS_VSCROLL: u32 = 0x0020_0000;
const WS_TABSTOP: u32 = 0x0001_0000;
const WS_EX_CLIENTEDGE: u32 = 0x0200;
const DS_SETFONT: u32 = 0x40;
const DS_MODALFRAME: u32 = 0x80;
const ES_PASSWORD: u32 = 0x20;
const ES_AUTOHSCROLL: u32 = 0x80;
const SS_CENTER: u32 = 0x01;
const SS_NOPREFIX: u32 = 0x80;
const SS_ENDELLIPSIS: u32 = 0x4000;
const BS_DEFPUSHBUTTON: u32 = 0x01;
const LBS_NOTIFY: u32 = 0x01;
const LBS_OWNERDRAWFIXED: u32 = 0x10;
const LBS_NOINTEGRALHEIGHT: u32 = 0x100;
const CBS_DROPDOWNLIST: u32 = 0x03;

const EM_SETSEL: u32 = 0x00B1;
const EM_LIMITTEXT: u32 = 0x00C5;
const EM_EMPTYUNDOBUFFER: u32 = 0x00CD;
const EM_SETCUEBANNER: u32 = 0x1501;
const LB_ADDSTRING: u32 = 0x0180;
const LB_RESETCONTENT: u32 = 0x0184;
const LB_SETCURSEL: u32 = 0x0186;
const LB_GETCURSEL: u32 = 0x0188;
const LB_SETITEMHEIGHT: u32 = 0x01A0;
const CB_ADDSTRING: u32 = 0x0143;
const CB_GETCURSEL: u32 = 0x0147;
const CB_SETCURSEL: u32 = 0x014E;
const EN_CHANGE: usize = 0x0300;
const LBN_SELCHANGE: usize = 1;
const LBN_DBLCLK: usize = 2;
const CBN_SELCHANGE: usize = 1;
const BN_CLICKED: usize = 0;
const GWLP_USERDATA: i32 = -21;

const MB_ICONERROR: u32 = 0x10;
const MB_ICONWARNING: u32 = 0x30;
const MB_YESNO: u32 = 0x04;
const MB_OKCANCEL: u32 = 0x01;
const MB_DEFBUTTON2: u32 = 0x100;
const IDYES: i32 = 6;

const IDOK: usize = 1;
const IDCANCEL: usize = 2;
const ID_PASS: usize = 100;
const ID_CONFIRM: usize = 101;
const ID_UNLOCK: usize = 110;
const ID_LOCK: usize = 111;
const ID_SEARCH: usize = 120;
const ID_LIST: usize = 121;
const ID_COPY: usize = 130;
const ID_ADD: usize = 131;
const ID_DELETE: usize = 132;
const ID_FOCUS_SEARCH: usize = 140;
const ID_TITLE: usize = 200;
const ID_SUBTITLE: usize = 201;
const ID_PASS_LABEL: usize = 202;
const ID_CONFIRM_LABEL: usize = 203;
const ID_CAPS: usize = 204;
const ID_INFO: usize = 205;
const ID_STATUS: usize = 206;
const ID_EMPTY: usize = 207;
const TIMER_TICK: usize = 1;

const IDLE_LOCK: Duration = Duration::from_secs(300);
const CLIPBOARD_CLEAR: Duration = Duration::from_secs(30);
const STATUS_TTL: Duration = Duration::from_secs(6);
const MIN_PASSWORD_CHARS: usize = 12;
const ROW_HEIGHT: i32 = 62;
/// List item heights are limited to 255 px (reached above ~400% scaling).
fn row_height() -> i32 {
    sc(ROW_HEIGHT).min(255)
}

const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}
const TEXT: u32 = rgb(32, 33, 36);
const GRAY: u32 = rgb(95, 99, 104);
const ACCENT: u32 = rgb(26, 115, 232);
const RED: u32 = rgb(197, 34, 31);
const ORANGE: u32 = rgb(176, 96, 0);
const SELECTED: u32 = rgb(232, 240, 254);
const LINE: u32 = rgb(226, 228, 232);
const WHITE: u32 = rgb(255, 255, 255);

const LOCKED: &str = "보관함이 잠겨 있습니다.";
const LOCKED_IDLE: &str = "5분 동안 사용하지 않아 잠겼습니다.";
const LOCKED_SESSION: &str = "Windows 잠금 또는 절전으로 잠겼습니다.";
const CHANGED_ELSEWHERE: &str = "보관함 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.";
const NEW_INFO: &str = "이 보관함은 복원할 수 없도록 만들어집니다.\n\n\
• 비밀키는 이 PC의 TPM과 비밀번호로 암호화되며, 다시 보거나 내보낼 수 없습니다.\n\
• 비밀번호 분실, TPM 초기화·교체, Windows 사용자 프로필 손실 시 복구할 수 없습니다.\n\
• 각 서비스의 원본 시크릿키(또는 복구 코드)는 반드시 별도의 안전한 곳에 보관하세요.";
const OPEN_INFO: &str = "5분 동안 사용하지 않거나 Windows를 잠그면 자동으로 잠깁니다.\n\
비밀번호를 잊으면 이 보관함은 복구할 수 없습니다.";
const CREATE_WARNING: &str = "새 보관함을 만듭니다.\n\n\
이 보관함은 복원할 수 없습니다. 비밀번호를 잊거나 TPM·Windows 사용자 프로필이 초기화되면 \
저장된 계정은 영구히 사라집니다.\n\n\
각 서비스의 원본 시크릿키를 별도의 안전한 곳에 보관했는지 확인하세요. 계속할까요?";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn path_wide(s: &Path) -> Vec<u16> {
    s.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn wipe(bytes: &mut [u8]) {
    for b in bytes {
        unsafe { std::ptr::write_volatile(b, 0) }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
fn wipe_string(s: &mut str) {
    unsafe { wipe(s.as_bytes_mut()) }
}
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0)
    }
}
/// Text read from an input control; cleared on drop.
struct SecretText(String);
impl Drop for SecretText {
    fn drop(&mut self) {
        wipe_string(&mut self.0)
    }
}
impl Deref for SecretText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}
struct Entry {
    name: String,
    secret: Secret,
    algorithm: otp::Algorithm,
    digits: u32,
    period: u64,
}
struct OwnedHandle(H);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn serialize<'a, I>(entries: I) -> Result<Vec<u8>, String>
where
    I: IntoIterator<Item = &'a Entry>,
    I::IntoIter: Clone,
{
    let entries = entries.into_iter();
    let count = entries.clone().count();
    if count > 1000 {
        return Err("계정이 너무 많습니다.".into());
    }
    // Allocate once so a resize never frees an earlier copy of plaintext keys.
    let mut size = 12usize;
    for entry in entries.clone() {
        if entry.name.is_empty()
            || entry.name.len() > 1024
            || entry.secret.0.is_empty()
            || entry.secret.0.len() > 4096
        {
            return Err("계정 데이터 크기가 올바르지 않습니다.".into());
        }
        if !matches!(entry.digits, 6 | 8) || !matches!(entry.period, 30 | 60) {
            return Err("지원하지 않는 OTP 설정입니다.".into());
        }
        size = size
            .checked_add(11 + entry.name.len() + entry.secret.0.len())
            .ok_or("보관함 크기 오류")?;
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(b"LOTP0002");
    out.extend_from_slice(&(count as u32).to_le_bytes());
    for e in entries {
        let n = e.name.as_bytes();
        let s = &e.secret.0;
        out.extend_from_slice(&(n.len() as u32).to_le_bytes());
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.push(match e.algorithm {
            otp::Algorithm::Sha1 => 1,
            otp::Algorithm::Sha256 => 2,
            otp::Algorithm::Sha512 => 3,
        });
        out.push(e.digits as u8);
        out.push(e.period as u8);
        out.extend_from_slice(n);
        out.extend_from_slice(s);
    }
    debug_assert_eq!(out.len(), size);
    Ok(out)
}
fn deserialize(data: &[u8]) -> Result<Vec<Entry>, String> {
    if data.len() < 12 || (&data[..8] != b"LOTP0001" && &data[..8] != b"LOTP0002") {
        return Err("보관함 형식이 올바르지 않습니다.".into());
    }
    let v2 = &data[..8] == b"LOTP0002";
    let mut p = 8;
    fn read(data: &[u8], p: &mut usize) -> Result<usize, String> {
        let end = p.checked_add(4).ok_or("길이 오류")?;
        let b = data.get(*p..end).ok_or("데이터가 잘렸습니다")?;
        *p = end;
        Ok(u32::from_le_bytes(b.try_into().unwrap()) as usize)
    }
    let count = read(data, &mut p)?;
    if count > 1000 {
        return Err("계정이 너무 많습니다.".into());
    }
    let mut result = Vec::new();
    for _ in 0..count {
        let n = read(data, &mut p)?;
        let s = read(data, &mut p)?;
        if n == 0 || n > 1024 || s == 0 || s > 4096 {
            return Err("데이터 길이가 올바르지 않습니다.".into());
        }
        let (algorithm, digits, period) = if v2 {
            let end = p.checked_add(3).ok_or("길이 오류")?;
            let params = data.get(p..end).ok_or("데이터가 잘렸습니다")?;
            p = end;
            let algorithm = match params[0] {
                1 => otp::Algorithm::Sha1,
                2 => otp::Algorithm::Sha256,
                3 => otp::Algorithm::Sha512,
                _ => return Err("지원하지 않는 OTP 알고리즘입니다.".into()),
            };
            let digits = u32::from(params[1]);
            let period = u64::from(params[2]);
            if !matches!(digits, 6 | 8) || !matches!(period, 30 | 60) {
                return Err("지원하지 않는 OTP 설정입니다.".into());
            }
            (algorithm, digits, period)
        } else {
            (otp::Algorithm::Sha1, 6, 30)
        };
        let end = p.checked_add(n).ok_or("길이 오류")?;
        let name = std::str::from_utf8(data.get(p..end).ok_or("데이터가 잘렸습니다")?)
            .map_err(|_| "계정 이름 오류")?
            .to_string();
        p = end;
        let end = p.checked_add(s).ok_or("길이 오류")?;
        let secret = data.get(p..end).ok_or("데이터가 잘렸습니다")?.to_vec();
        p = end;
        result.push(Entry {
            name,
            secret: Secret(secret),
            algorithm,
            digits,
            period,
        });
    }
    if p != data.len() {
        return Err("보관함에 예상하지 못한 데이터가 있습니다.".into());
    }
    Ok(result)
}
fn read_vault_bytes(path: &Path) -> Result<Vec<u8>, String> {
    const LIMIT: u64 = vault::MAX_FILE as u64;
    let file = fs::File::open(path).map_err(|e| format!("보관함을 읽을 수 없습니다: {e}"))?;
    let mut data = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("보관함 읽기 실패: {e}"))?;
    if data.len() as u64 > LIMIT {
        return Err("보관함이 너무 큽니다.".into());
    }
    Ok(data)
}
/// Atomically write an encrypted vault. With `expected`, the current file must
/// still be exactly that blob; without it, an existing file is never replaced.
fn write_vault(path: &Path, ciphertext: &[u8], expected: Option<&[u8]>) -> Result<(), String> {
    let parent = path.parent().ok_or("저장 위치 오류")?;
    fs::create_dir_all(parent).map_err(|e| format!("폴더 생성 실패: {e}"))?;
    let unchanged = || -> Result<(), String> {
        match expected {
            None if path.exists() => Err("기존 보관함이 있어 새로 만들 수 없습니다.".into()),
            Some(original) if read_vault_bytes(path)? != original => Err(CHANGED_ELSEWHERE.into()),
            _ => Ok(()),
        }
    };
    unchanged()?;
    let tmp = parent.join(format!(
        "vault-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("임시 파일 생성 실패: {e}"))?;
        f.write_all(ciphertext)
            .map_err(|e| format!("저장 실패: {e}"))?;
        f.sync_all().map_err(|e| format!("동기화 실패: {e}"))?;
        drop(f);
        unchanged()?;
        // MOVEFILE_WRITE_THROUGH, plus MOVEFILE_REPLACE_EXISTING for updates.
        let flags = if expected.is_none() { 8 } else { 8 | 1 };
        if unsafe { MoveFileExW(path_wide(&tmp).as_ptr(), path_wide(path).as_ptr(), flags) } == 0 {
            return Err(format!(
                "보관함 교체 실패: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// GDI resources and cross-cutting flags. Plain cells, so window procedures
/// can read them even while `APP` is borrowed by an outer handler.
struct Ui {
    dpi: Cell<u32>,
    font: Cell<H>,
    bold: Cell<H>,
    small: Cell<H>,
    title: Cell<H>,
    code: Cell<H>,
    warn_info: Cell<bool>,
    dialog: Cell<H>,
    pending_lock: Cell<Option<&'static str>>,
}
struct Row {
    entry: usize,
    counter: u64,
    name: String,
    meta: String,
    code: String,
    remaining: u64,
    period: u64,
}
struct Controls {
    title: H,
    subtitle: H,
    pass_label: H,
    pass: H,
    confirm_label: H,
    confirm: H,
    caps: H,
    unlock: H,
    info: H,
    search: H,
    lock: H,
    list: H,
    empty: H,
    copy: H,
    add: H,
    delete: H,
    status: H,
}
struct Session {
    key: vault::VaultKey,
    blob: Vec<u8>,
    entries: Vec<Entry>,
}
struct App {
    hwnd: H,
    _lock: OwnedHandle,
    path: PathBuf,
    c: Controls,
    session: Option<Session>,
    /// Incremented on every lock. An action that showed a dialog compares it
    /// before committing, so nothing is saved after a lock during the dialog.
    generation: u64,
    new_vault: bool,
    last_activity: Instant,
    visible: Vec<usize>,
    filter: String,
    focus: H,
    clipboard: Option<(u32, Instant)>,
    status: Option<(String, Instant)>,
    last_second: u64,
    lock_reason: &'static str,
}

thread_local! {
    static UI: Ui = const {
        Ui {
            dpi: Cell::new(96),
            font: Cell::new(null_mut()),
            bold: Cell::new(null_mut()),
            small: Cell::new(null_mut()),
            title: Cell::new(null_mut()),
            code: Cell::new(null_mut()),
            warn_info: Cell::new(false),
            dialog: Cell::new(null_mut()),
            pending_lock: Cell::new(None),
        }
    };
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    static ROWS: RefCell<Vec<Row>> = const { RefCell::new(Vec::new()) };
}
fn ui<R>(f: impl FnOnce(&Ui) -> R) -> R {
    UI.with(f)
}
/// Run `f` with the app state. Returns None when the state is absent or already
/// borrowed by an outer handler (synchronous re-entry from a control). Never
/// show a modal dialog inside `f`: that would hold the borrow across a nested
/// message loop and delay locking.
fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        guard.as_mut().map(f)
    })
}
fn sc(v: i32) -> i32 {
    unsafe { MulDiv(v, ui(|u| u.dpi.get()) as i32, 96) }
}

unsafe fn make_font(tenth_points: i32, weight: i32, face: &str, dpi: u32) -> H {
    CreateFontW(
        -MulDiv(tenth_points, dpi as i32, 720),
        0,
        0,
        0,
        weight,
        0,
        0,
        0,
        1, // DEFAULT_CHARSET
        0,
        0,
        5, // CLEARTYPE_QUALITY
        0,
        wide(face).as_ptr(),
    )
}
/// Create fonts for `dpi` and return the previous ones, to be deleted after
/// the controls have been switched to the new fonts.
unsafe fn create_fonts(dpi: u32) -> Vec<H> {
    ui(|u| {
        u.dpi.set(dpi);
        [
            (&u.font, make_font(95, 400, "Malgun Gothic", dpi)),
            (&u.bold, make_font(105, 700, "Malgun Gothic", dpi)),
            (&u.small, make_font(85, 400, "Malgun Gothic", dpi)),
            (&u.title, make_font(180, 700, "Malgun Gothic", dpi)),
            (&u.code, make_font(200, 700, "Consolas", dpi)),
        ]
        .into_iter()
        .map(|(cell, font)| cell.replace(font))
        .filter(|old| !old.is_null())
        .collect()
    })
}
unsafe fn delete_fonts(fonts: Vec<H>) {
    for font in fonts {
        DeleteObject(font);
    }
}
unsafe fn apply_fonts(c: &Controls) {
    let (font, title) = ui(|u| (u.font.get(), u.title.get()));
    for h in [
        c.subtitle,
        c.pass_label,
        c.pass,
        c.confirm_label,
        c.confirm,
        c.caps,
        c.unlock,
        c.info,
        c.search,
        c.lock,
        c.list,
        c.empty,
        c.copy,
        c.add,
        c.delete,
        c.status,
    ] {
        SendMessageW(h, WM_SETFONT, font as usize, 1);
    }
    SendMessageW(c.title, WM_SETFONT, title as usize, 1);
}

unsafe fn control(parent: H, class: &str, text: &str, style: u32, ex: u32, id: usize) -> H {
    let tab = if matches!(class, "EDIT" | "BUTTON" | "LISTBOX") {
        WS_TABSTOP
    } else {
        0
    };
    CreateWindowExW(
        ex,
        wide(class).as_ptr(),
        wide(text).as_ptr(),
        WS_CHILD | tab | style,
        0,
        0,
        0,
        0,
        parent,
        id as H,
        GetModuleHandleW(null()),
        null_mut(),
    )
}
unsafe fn set(h: H, s: &str) {
    SetWindowTextW(h, wide(s).as_ptr());
}
/// Read a control's text without keeping an uncleared UTF-16 copy.
unsafe fn get_text(h: H) -> SecretText {
    let n = GetWindowTextLengthW(h).clamp(0, 8192) as usize;
    let mut b = vec![0u16; n + 1];
    let got = (GetWindowTextW(h, b.as_mut_ptr(), (n + 1) as i32).max(0) as usize).min(n);
    // One UTF-16 unit is at most 3 UTF-8 bytes: reserve once so a reallocation
    // never frees an unwiped partial copy of a password or secret.
    let mut s = String::with_capacity(got * 3);
    for c in char::decode_utf16(b[..got].iter().copied()) {
        s.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    for v in &mut b {
        std::ptr::write_volatile(v, 0)
    }
    SecretText(s)
}
unsafe fn set_if_changed(h: H, s: &str) {
    if *get_text(h) != *s {
        set(h, s);
    }
}
unsafe fn clear_edit(h: H) {
    set(h, "");
    SendMessageW(h, EM_EMPTYUNDOBUFFER, 0, 0);
}
unsafe fn notice(h: H, s: &str) {
    MessageBoxW(
        h,
        wide(s).as_ptr(),
        wide("Local OTP").as_ptr(),
        MB_ICONERROR,
    );
}
unsafe fn place(h: H, x: i32, y: i32, w: i32, height: i32) {
    MoveWindow(h, x, y, w.max(0), height.max(0), 1);
}
unsafe fn show(h: H, visible: bool) {
    ShowWindow(h, if visible { 5 } else { 0 });
}
/// Keep OTP codes out of screenshots, screen recording and screen sharing.
unsafe fn protect_window(h: H) {
    const WDA_MONITOR: u32 = 0x01;
    const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;
    if SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE) == 0 {
        SetWindowDisplayAffinity(h, WDA_MONITOR);
    }
}
/// Drop keys pressed during a slow TPM operation, so an extra Enter typed while
/// unlocking does not copy a code (or retry) once the operation finishes.
unsafe fn discard_typeahead() {
    let mut msg: Msg = zeroed();
    while PeekMessageW(&mut msg, null_mut(), WM_KEYDOWN, 0x0109, 1) != 0 {}
}
unsafe fn wait_cursor() {
    SetCursor(LoadCursorW(null_mut(), 32514usize as *const u16));
}

fn algorithm_name(a: otp::Algorithm) -> &'static str {
    match a {
        otp::Algorithm::Sha1 => "SHA-1",
        otp::Algorithm::Sha256 => "SHA-256",
        otp::Algorithm::Sha512 => "SHA-512",
    }
}
/// "123456" -> "123 456", "12345678" -> "1234 5678".
fn group_code(code: &str) -> String {
    let mid = code.len() / 2;
    format!("{} {}", &code[..mid], &code[mid..])
}

unsafe fn show_page(a: &mut App) {
    let unlocked = a.session.is_some();
    a.new_vault = !unlocked && !a.path.exists();
    let c = &a.c;
    for h in [
        c.title,
        c.subtitle,
        c.pass_label,
        c.pass,
        c.caps,
        c.unlock,
        c.info,
    ] {
        show(h, !unlocked);
    }
    for h in [c.confirm_label, c.confirm] {
        show(h, a.new_vault);
    }
    for h in [c.search, c.lock, c.copy, c.add, c.delete, c.status] {
        show(h, unlocked);
    }
    if !unlocked {
        show(c.list, false);
        show(c.empty, false);
        if a.new_vault {
            set(
                c.subtitle,
                "새 보관함 — 12자 이상의 길고 고유한 비밀번호를 정하세요.",
            );
            set(c.pass_label, "새 비밀번호");
            set(c.unlock, "보관함 만들기");
            set(c.info, NEW_INFO);
        } else {
            set(c.subtitle, a.lock_reason);
            set(c.pass_label, "비밀번호");
            set(c.unlock, "잠금 해제");
            set(c.info, OPEN_INFO);
        }
        ui(|u| u.warn_info.set(a.new_vault));
        update_caps(a);
    }
    layout(a);
}
unsafe fn layout(a: &App) {
    let mut r = Rect::default();
    GetClientRect(a.hwnd, &mut r);
    let (w, h) = (r.right, r.bottom);
    let m = sc(16);
    let c = &a.c;
    if a.session.is_none() {
        let cw = (w - 2 * m).min(sc(380));
        let x = (w - cw) / 2;
        let mut y = sc(32);
        place(c.title, x, y, cw, sc(40));
        y += sc(44);
        place(c.subtitle, x, y, cw, sc(40));
        y += sc(48);
        place(c.pass_label, x, y, cw, sc(20));
        y += sc(22);
        place(c.pass, x, y, cw, sc(28));
        y += sc(36);
        if a.new_vault {
            place(c.confirm_label, x, y, cw, sc(20));
            y += sc(22);
            place(c.confirm, x, y, cw, sc(28));
            y += sc(36);
        }
        place(c.caps, x, y, cw, sc(20));
        y += sc(24);
        place(c.unlock, x, y, cw, sc(36));
        y += sc(52);
        place(c.info, x, y, cw, (h - y - m).max(sc(40)));
    } else {
        let bh = sc(32);
        let lock_w = sc(84);
        place(c.search, m, m, w - 2 * m - lock_w - sc(8), bh);
        place(c.lock, w - m - lock_w, m, lock_w, bh);
        let status_h = sc(20);
        let buttons_y = h - m - status_h - sc(8) - bh;
        let list_y = m + bh + sc(10);
        let list_h = (buttons_y - sc(10) - list_y).max(sc(62));
        place(c.list, m, list_y, w - 2 * m, list_h);
        place(c.empty, m, list_y + list_h / 2 - sc(30), w - 2 * m, sc(60));
        let copy_w = sc(96);
        let add_w = sc(104);
        let delete_w = sc(80);
        place(c.copy, m, buttons_y, copy_w, bh);
        place(c.add, m + copy_w + sc(8), buttons_y, add_w, bh);
        place(c.delete, w - m - delete_w, buttons_y, delete_w, bh);
        place(c.status, m, h - m - status_h, w - 2 * m, status_h);
    }
}
unsafe fn update_caps(a: &App) {
    let on = GetKeyState(0x14) & 1 != 0;
    set_if_changed(
        a.c.caps,
        if on {
            "Caps Lock이 켜져 있습니다."
        } else {
            ""
        },
    );
}
fn selected_entry(a: &App) -> Option<usize> {
    let sel = unsafe { SendMessageW(a.c.list, LB_GETCURSEL, 0, 0) };
    usize::try_from(sel)
        .ok()
        .and_then(|i| a.visible.get(i).copied())
}
unsafe fn update_buttons(a: &App) {
    let has = selected_entry(a).is_some();
    EnableWindow(a.c.copy, i32::from(has));
    EnableWindow(a.c.delete, i32::from(has));
}
/// Rebuild the visible list for the current filter and select `keep`.
unsafe fn sync_list(a: &mut App, keep: Option<usize>) {
    let filter = a.filter.trim().to_lowercase();
    let (visible, total) = match &a.session {
        Some(s) => (
            s.entries
                .iter()
                .enumerate()
                .filter(|(_, e)| filter.is_empty() || e.name.to_lowercase().contains(&filter))
                .map(|(i, _)| i)
                .collect::<Vec<_>>(),
            s.entries.len(),
        ),
        None => return,
    };
    a.visible = visible;
    SendMessageW(a.c.list, LB_RESETCONTENT, 0, 0);
    for _ in &a.visible {
        SendMessageW(a.c.list, LB_ADDSTRING, 0, 0);
    }
    let selection = keep
        .and_then(|e| a.visible.iter().position(|&i| i == e))
        .or(if a.visible.is_empty() { None } else { Some(0) });
    if let Some(p) = selection {
        SendMessageW(a.c.list, LB_SETCURSEL, p, 0);
    }
    ROWS.with(|r| {
        if let Ok(mut r) = r.try_borrow_mut() {
            r.clear()
        }
    });
    update_rows(a, now_secs());
    let empty = a.visible.is_empty();
    show(a.c.list, !empty);
    show(a.c.empty, empty);
    set(
        a.c.empty,
        if total == 0 {
            "등록된 계정이 없습니다.\n‘계정 추가…’를 눌러 서비스의 원본 시크릿키를 입력하세요."
        } else {
            "검색 결과가 없습니다."
        },
    );
    update_buttons(a);
    // Deleting the last (visible) account can disable or hide the focused control.
    let focus = GetFocus();
    if IsChild(a.hwnd, focus) != 0 && (IsWindowVisible(focus) == 0 || IsWindowEnabled(focus) == 0) {
        SetFocus(default_focus(a));
    }
}
/// Recompute display rows; codes are recomputed only when their time step changes.
unsafe fn update_rows(a: &App, now: u64) {
    let Some(s) = &a.session else { return };
    ROWS.with(|rows| {
        let Ok(mut rows) = rows.try_borrow_mut() else {
            return;
        };
        let old = std::mem::take(&mut *rows);
        for (pos, &i) in a.visible.iter().enumerate() {
            let e = &s.entries[i];
            let counter = now / e.period;
            let code = match old.get(pos) {
                Some(r) if r.entry == i && r.counter == counter => r.code.clone(),
                _ => otp::totp(&e.secret.0, now, e.period, e.digits, e.algorithm)
                    .map(|c| group_code(&c))
                    .unwrap_or_else(|_| "오류".into()),
            };
            rows.push(Row {
                entry: i,
                counter,
                name: e.name.clone(),
                meta: format!(
                    "{} · {}자리 · {}초",
                    algorithm_name(e.algorithm),
                    e.digits,
                    e.period
                ),
                code,
                remaining: e.period - now % e.period,
                period: e.period,
            });
        }
    });
    InvalidateRect(a.c.list, null(), 0);
}
unsafe fn update_status(a: &mut App) {
    if a.status
        .as_ref()
        .is_some_and(|(_, t)| t.elapsed() >= STATUS_TTL)
    {
        a.status = None;
    }
    let text = match &a.status {
        Some((message, _)) => message.clone(),
        None => {
            let left = IDLE_LOCK
                .saturating_sub(a.last_activity.elapsed())
                .as_secs();
            format!(
                "더블클릭 또는 Enter로 코드 복사 · 자동 잠금 {}:{:02}",
                left / 60,
                left % 60
            )
        }
    };
    set_if_changed(a.c.status, &text);
}
unsafe fn notify(a: &mut App, message: String) {
    a.status = Some((message, Instant::now()));
    update_status(a);
}

unsafe fn set_clipboard_data(format: u32, bytes: &[u8]) -> Result<(), String> {
    let memory = GlobalAlloc(0x0002, bytes.len().max(1)); // GMEM_MOVEABLE
    if memory.is_null() {
        return Err("클립보드 메모리를 할당할 수 없습니다.".into());
    }
    let p = GlobalLock(memory) as *mut u8;
    if p.is_null() {
        GlobalFree(memory);
        return Err("클립보드 메모리를 사용할 수 없습니다.".into());
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
    GlobalUnlock(memory);
    if SetClipboardData(format, memory).is_null() {
        GlobalFree(memory);
        return Err("클립보드에 복사하지 못했습니다.".into());
    }
    Ok(())
}
/// Other programs (clipboard managers, RDP) briefly hold the clipboard open.
unsafe fn open_clipboard(owner: H) -> bool {
    for attempt in 0..10 {
        if OpenClipboard(owner) != 0 {
            return true;
        }
        if attempt < 9 {
            Sleep(20);
        }
    }
    false
}
/// Copy text and return the clipboard sequence number identifying our copy.
unsafe fn copy_to_clipboard(owner: H, text: &str) -> Result<u32, String> {
    if !open_clipboard(owner) {
        return Err("클립보드를 열 수 없습니다. 다른 프로그램이 사용 중일 수 있습니다.".into());
    }
    let result = (|| {
        if EmptyClipboard() == 0 {
            return Err("클립보드를 비울 수 없습니다.".to_string());
        }
        let w = wide(text);
        set_clipboard_data(
            13, // CF_UNICODETEXT
            std::slice::from_raw_parts(w.as_ptr().cast(), w.len() * 2),
        )?;
        // Keep the code out of Windows clipboard history and cloud clipboard.
        for name in [
            "ExcludeClipboardContentFromMonitorProcessing",
            "CanIncludeInClipboardHistory",
            "CanUploadToCloudClipboard",
        ] {
            let format = RegisterClipboardFormatW(wide(name).as_ptr());
            if format != 0 {
                let _ = set_clipboard_data(format, &0u32.to_le_bytes());
            }
        }
        Ok(())
    })();
    // The sequence number changes when the clipboard is closed, so it must be
    // read afterwards (reading it while open records a stale value).
    CloseClipboard();
    result?;
    Ok(GetClipboardSequenceNumber())
}
/// Clear the clipboard only if it still holds the code this app copied.
/// If the clipboard is busy the record is kept and the next tick retries.
unsafe fn clear_our_clipboard(a: &mut App) -> bool {
    let Some((seq, _)) = a.clipboard else {
        return false;
    };
    if GetClipboardSequenceNumber() != seq {
        a.clipboard = None; // Something else was copied since; leave it alone.
        return false;
    }
    if !open_clipboard(a.hwnd) {
        return false;
    }
    if GetClipboardSequenceNumber() == seq {
        EmptyClipboard();
    }
    CloseClipboard();
    a.clipboard = None;
    true
}
unsafe fn copy_selected(a: &mut App) -> Result<(), String> {
    let Some(s) = &a.session else { return Ok(()) };
    let idx = selected_entry(a).ok_or("복사할 계정을 선택하세요.")?;
    let e = &s.entries[idx];
    let now = now_secs();
    let code = otp::totp(&e.secret.0, now, e.period, e.digits, e.algorithm)?;
    let (name, left) = (e.name.clone(), e.period - now % e.period);
    let seq = copy_to_clipboard(a.hwnd, &code)?;
    a.clipboard = Some((seq, Instant::now()));
    notify(
        a,
        format!("‘{name}’ 코드를 복사했습니다 ({left}초 남음). 30초 후 클립보드에서 지웁니다."),
    );
    Ok(())
}

unsafe fn default_focus(a: &App) -> H {
    if a.session.is_none() {
        a.c.pass
    } else if a.visible.is_empty() {
        a.c.add
    } else {
        a.c.list
    }
}
unsafe fn focus_default(a: &mut App) {
    a.focus = null_mut();
    if GetForegroundWindow() == a.hwnd {
        SetFocus(default_focus(a));
    }
}
/// Lock immediately: wipe secrets, the derived key, display rows and our
/// clipboard contents, and cancel any open dialog. Returns false when the state
/// is busy; the caller then defers the lock with `request_lock`.
unsafe fn lock_now(reason: &'static str) -> bool {
    let done = with_app(|a| {
        a.generation += 1;
        let was_open = a.session.take().is_some();
        clear_our_clipboard(a);
        a.visible.clear();
        a.filter.clear();
        a.status = None;
        ROWS.with(|r| {
            if let Ok(mut r) = r.try_borrow_mut() {
                r.clear()
            }
        });
        SendMessageW(a.c.list, LB_RESETCONTENT, 0, 0);
        for h in [a.c.pass, a.c.confirm, a.c.search] {
            clear_edit(h);
        }
        if was_open {
            a.lock_reason = reason;
        }
        show_page(a);
        focus_default(a);
    })
    .is_some();
    if done {
        let dialog = ui(|u| u.dialog.get());
        if !dialog.is_null() {
            // Clear now: a nested message box can delay the dialog's destruction.
            for id in [ID_SECRET, ID_PASSWORD] {
                let edit = GetDlgItem(dialog, id);
                if !edit.is_null() {
                    clear_edit(edit);
                }
            }
            EndDialog(dialog, 0);
        }
    }
    done
}
unsafe fn request_lock(reason: &'static str) {
    if !lock_now(reason) {
        ui(|u| u.pending_lock.set(Some(reason)));
    }
}
fn touch() {
    with_app(|a| a.last_activity = Instant::now());
}
unsafe fn tick() {
    let idle = with_app(|a| {
        if a.session.is_none() {
            // Retry a clear that failed at lock time because the clipboard was busy.
            clear_our_clipboard(a);
            update_caps(a);
            return false;
        }
        if a.last_activity.elapsed() >= IDLE_LOCK {
            return true;
        }
        if a.clipboard
            .is_some_and(|(_, t)| t.elapsed() >= CLIPBOARD_CLEAR)
            && clear_our_clipboard(a)
        {
            notify(a, "클립보드의 코드를 지웠습니다.".into());
        }
        let now = now_secs();
        if now != a.last_second {
            a.last_second = now;
            update_rows(a, now);
        }
        update_status(a);
        false
    });
    if idle == Some(true) {
        request_lock(LOCKED_IDLE);
    }
}

unsafe fn unlock(hwnd: H) {
    enum Plan {
        Open(PathBuf, SecretText),
        Create(PathBuf, SecretText),
    }
    let plan = with_app(|a| -> Result<(Plan, u64), String> {
        if a.session.is_some() {
            return Err(String::new());
        }
        if a.path.exists() == a.new_vault {
            // The vault file appeared or vanished since this page was shown.
            show_page(a);
            return Err(String::new());
        }
        let generation = a.generation;
        let pass = get_text(a.c.pass);
        if pass.is_empty() {
            SetFocus(a.c.pass);
            return Err("비밀번호를 입력하세요.".into());
        }
        if a.path.exists() {
            clear_edit(a.c.pass);
            clear_edit(a.c.confirm);
            return Ok((Plan::Open(a.path.clone(), pass), generation));
        }
        if pass.chars().count() < MIN_PASSWORD_CHARS {
            SetFocus(a.c.pass);
            return Err(format!(
                "새 보관함 비밀번호는 {MIN_PASSWORD_CHARS}자 이상이어야 합니다."
            ));
        }
        if *pass != *get_text(a.c.confirm) {
            clear_edit(a.c.confirm);
            SetFocus(a.c.confirm);
            return Err("비밀번호 확인이 일치하지 않습니다.".into());
        }
        Ok((Plan::Create(a.path.clone(), pass), generation))
    });
    let (plan, generation) = match plan {
        Some(Ok(plan)) => plan,
        Some(Err(e)) if !e.is_empty() => return notice(hwnd, &e),
        _ => return,
    };
    if let Plan::Create(..) = plan {
        let answer = MessageBoxW(
            hwnd,
            wide(CREATE_WARNING).as_ptr(),
            wide("보관함 만들기").as_ptr(),
            MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2,
        );
        // Never create after a lock (Win+L, suspend) while the warning was open.
        let still_valid = with_app(|a| {
            let valid = a.generation == generation && !a.path.exists();
            if valid && answer == IDOK as i32 {
                clear_edit(a.c.pass);
                clear_edit(a.c.confirm);
            }
            valid
        });
        if answer != IDOK as i32 || still_valid != Some(true) {
            return;
        }
    }
    with_app(|a| {
        set(a.c.subtitle, "확인 중…");
        UpdateWindow(a.c.subtitle);
    });
    wait_cursor();
    let result: Result<Session, String> = match &plan {
        Plan::Open(path, pass) => (|| {
            let blob = read_vault_bytes(path)?;
            let (plain, key) = vault::open(pass, &blob)?;
            let plain = Secret(plain);
            let entries = deserialize(&plain.0)?;
            Ok(Session { key, blob, entries })
        })(),
        Plan::Create(path, pass) => (|| {
            let plain = Secret(serialize(std::iter::empty::<&Entry>())?);
            let (blob, key) = vault::create(pass, &plain.0)?;
            write_vault(path, &blob, None)?;
            Ok(Session {
                key,
                blob,
                entries: Vec::new(),
            })
        })(),
    };
    let created = matches!(plan, Plan::Create(..));
    drop(plan);
    discard_typeahead();
    match result {
        Ok(session) => {
            with_app(move |a| {
                a.session = Some(session);
                a.last_activity = Instant::now();
                a.filter.clear();
                show_page(a);
                sync_list(a, None);
                focus_default(a);
                notify(
                    a,
                    if created {
                        "새 보관함을 만들었습니다. ‘계정 추가…’로 시작하세요.".into()
                    } else {
                        "보관함을 열었습니다.".into()
                    },
                );
            });
        }
        Err(e) => {
            with_app(|a| {
                show_page(a);
                focus_default(a);
            });
            notice(
                hwnd,
                &format!("보관함을 열지 못했습니다.\n\n{e}\n\n보관함 파일은 변경하지 않았습니다."),
            );
        }
    }
}
/// Re-encrypt `plain` over the vault this session opened, refusing to
/// overwrite a file that changed elsewhere.
fn commit(a: &mut App, plain: &Secret) -> Result<(), String> {
    let s = a.session.as_mut().ok_or("보관함이 잠겨 있습니다.")?;
    if read_vault_bytes(&a.path)? != s.blob {
        return Err(CHANGED_ELSEWHERE.into());
    }
    let blob = vault::reencrypt(&s.key, &plain.0, &s.blob)?;
    write_vault(&a.path, &blob, Some(&s.blob))?;
    s.blob = blob;
    Ok(())
}
unsafe fn add_account(hwnd: H) {
    let Some(Some((names, generation))) = with_app(|a| {
        a.session.as_ref().map(|s| {
            (
                s.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>(),
                a.generation,
            )
        })
    }) else {
        return;
    };
    let Some(entry) = run_add_dialog(hwnd, names) else {
        return;
    };
    wait_cursor();
    let result = with_app(move |a| -> Result<(), String> {
        if a.generation != generation {
            return Err(String::new()); // Locked while the dialog was open.
        }
        let s = a.session.as_ref().ok_or(String::new())?;
        let plain = Secret(serialize(s.entries.iter().chain(Some(&entry)))?);
        commit(a, &plain)?;
        let name = entry.name.clone();
        let s = a.session.as_mut().unwrap();
        s.entries.push(entry);
        let index = s.entries.len() - 1;
        a.filter.clear();
        clear_edit(a.c.search);
        sync_list(a, Some(index));
        notify(
            a,
            format!("‘{name}’ 계정을 추가했습니다. 기존 인증 앱의 코드와 같은지 확인하세요."),
        );
        Ok(())
    });
    if let Some(Err(e)) = result {
        if !e.is_empty() {
            notice(
                hwnd,
                &format!("계정을 추가하지 못했습니다.\n\n{e}\n\n보관함은 변경되지 않았습니다."),
            );
        }
    }
}
unsafe fn delete_account(hwnd: H) {
    let Some(Some((index, name, generation))) = with_app(|a| {
        let index = selected_entry(a)?;
        let s = a.session.as_ref()?;
        Some((index, s.entries[index].name.clone(), a.generation))
    }) else {
        return;
    };
    let Some(password) = run_confirm_dialog(hwnd, &name) else {
        return;
    };
    wait_cursor();
    let result = with_app(move |a| -> Result<(), String> {
        if a.generation != generation {
            return Err(String::new());
        }
        let s = a.session.as_ref().ok_or(String::new())?;
        if s.entries.get(index).map(|e| e.name.as_str()) != Some(name.as_str()) {
            return Err("선택한 계정이 바뀌었습니다. 다시 시도하세요.".into());
        }
        if !s.key.matches_password(&password)? {
            return Err("비밀번호가 올바르지 않습니다.".into());
        }
        let remaining = s
            .entries
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != index)
            .map(|(_, e)| e);
        let plain = Secret(serialize(remaining)?);
        commit(a, &plain)?;
        let s = a.session.as_mut().unwrap();
        s.entries.remove(index);
        let keep = if index < s.entries.len() {
            Some(index)
        } else {
            index.checked_sub(1)
        };
        sync_list(a, keep);
        notify(a, format!("‘{name}’ 계정을 삭제했습니다."));
        Ok(())
    });
    if let Some(Err(e)) = result {
        if !e.is_empty() {
            notice(
                hwnd,
                &format!("계정을 삭제하지 못했습니다.\n\n{e}\n\n보관함은 변경되지 않았습니다."),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory dialog templates (no resource compiler needed).

const BUTTON: u16 = 0x0080;
const EDIT: u16 = 0x0081;
const STATIC: u16 = 0x0082;
const COMBOBOX: u16 = 0x0085;

struct Template(Vec<u16>);
impl Template {
    fn new(title: &str, cx: i16, cy: i16) -> Self {
        let mut t = Template(Vec::new());
        t.dword(WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_SETFONT);
        t.dword(0);
        t.0.extend([0, 0, 0, cx as u16, cy as u16]); // item count, x, y, cx, cy
        t.0.extend([0, 0]); // no menu, default class
        t.text(title);
        t.0.push(9);
        t.text("Malgun Gothic");
        t
    }
    fn dword(&mut self, v: u32) {
        self.0.extend([v as u16, (v >> 16) as u16]);
    }
    fn text(&mut self, s: &str) {
        self.0.extend(s.encode_utf16().chain(Some(0)));
    }
    #[allow(clippy::too_many_arguments)]
    fn item(
        &mut self,
        class: u16,
        text: &str,
        style: u32,
        x: i16,
        y: i16,
        cx: i16,
        cy: i16,
        id: i32,
    ) {
        if self.0.len() % 2 == 1 {
            self.0.push(0); // DWORD alignment
        }
        let tab = if matches!(class, BUTTON | EDIT | COMBOBOX) {
            WS_TABSTOP
        } else {
            0
        };
        self.dword(WS_CHILD | WS_VISIBLE | tab | style);
        self.dword(0);
        self.0.extend([
            x as u16, y as u16, cx as u16, cy as u16, id as u16, 0xffff, class,
        ]);
        self.text(text);
        self.0.push(0); // no creation data
        self.0[4] += 1;
    }
    unsafe fn run(&self, owner: H, proc: WndProc, state: isize) -> isize {
        let aligned: Vec<u32> = self
            .0
            .chunks(2)
            .map(|c| u32::from(c[0]) | u32::from(c.get(1).copied().unwrap_or(0)) << 16)
            .collect();
        let result = DialogBoxIndirectParamW(
            GetModuleHandleW(null()),
            aligned.as_ptr().cast(),
            owner,
            Some(proc),
            state,
        );
        if result == -1 {
            notice(owner, "대화상자를 열 수 없습니다.");
        }
        result
    }
}
unsafe fn init_dialog(dlg: H, state: isize) {
    SetWindowLongPtrW(dlg, GWLP_USERDATA, state);
    ui(|u| u.dialog.set(dlg));
    protect_window(dlg);
    let owner = GetWindow(dlg, 4); // GW_OWNER
    let (mut o, mut d) = (Rect::default(), Rect::default());
    if !owner.is_null() && GetWindowRect(owner, &mut o) != 0 && GetWindowRect(dlg, &mut d) != 0 {
        let x = o.left + ((o.right - o.left) - (d.right - d.left)) / 2;
        let y = o.top + ((o.bottom - o.top) - (d.bottom - d.top)) / 3;
        SetWindowPos(
            dlg,
            null_mut(),
            x,
            y.max(o.top),
            0,
            0,
            0x0001 | 0x0004 | 0x0010,
        );
    }
}
unsafe fn dialog_state<'a, T>(dlg: H) -> Option<&'a T> {
    (GetWindowLongPtrW(dlg, GWLP_USERDATA) as *const T).as_ref()
}
unsafe fn static_color(dc: H, color: u32) -> isize {
    SetTextColor(dc, color);
    SetBkMode(dc, 1); // TRANSPARENT
    GetSysColorBrush(15) as isize // COLOR_BTNFACE, the dialog background
}

const ID_NAME: i32 = 1001;
const ID_SECRET: i32 = 1002;
const ID_ALGORITHM: i32 = 1003;
const ID_DIGITS: i32 = 1004;
const ID_PERIOD: i32 = 1005;
const ID_HINT: i32 = 1006;
const ID_CODE: i32 = 1007;
const ID_NOTE: i32 = 1008;
const ID_MESSAGE: i32 = 1101;
const ID_PASSWORD: i32 = 1102;

struct AddState {
    names: Vec<String>,
    result: RefCell<Option<Entry>>,
    font: Cell<H>,
    error: Cell<bool>,
    message: RefCell<Option<String>>,
}
struct Parsed {
    secret: Secret,
    link: Option<(String, otp::Algorithm, u32, u64)>,
}
/// Accept a Base32 secret or an otpauth://totp link.
fn parse_secret(text: &str) -> Result<Parsed, String> {
    let text = text.trim();
    if text
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("otpauth:"))
    {
        let mut link = otp::parse_otpauth(text)?;
        if !matches!(link.digits, 6 | 8) {
            return Err(format!(
                "6자리와 8자리만 지원합니다. (링크: {}자리)",
                link.digits
            ));
        }
        if !matches!(link.period, 30 | 60) {
            return Err(format!(
                "30초와 60초 주기만 지원합니다. (링크: {}초)",
                link.period
            ));
        }
        return Ok(Parsed {
            secret: Secret(std::mem::take(&mut link.secret)),
            link: Some((
                std::mem::take(&mut link.name),
                link.algorithm,
                link.digits,
                link.period,
            )),
        });
    }
    Ok(Parsed {
        secret: Secret(otp::decode_base32(text)?),
        link: None,
    })
}
unsafe fn selected_params(dlg: H) -> Result<(otp::Algorithm, u32, u64), String> {
    let pick = |id| SendMessageW(GetDlgItem(dlg, id), CB_GETCURSEL, 0, 0);
    let algorithm = match pick(ID_ALGORITHM) {
        0 => otp::Algorithm::Sha1,
        1 => otp::Algorithm::Sha256,
        2 => otp::Algorithm::Sha512,
        _ => return Err("알고리즘을 선택하세요.".into()),
    };
    let digits = match pick(ID_DIGITS) {
        0 => 6,
        1 => 8,
        _ => return Err("자릿수를 선택하세요.".into()),
    };
    let period = match pick(ID_PERIOD) {
        0 => 30,
        1 => 60,
        _ => return Err("주기를 선택하세요.".into()),
    };
    Ok((algorithm, digits, period))
}
unsafe fn update_preview(dlg: H, apply_link: bool) {
    let Some(st) = dialog_state::<AddState>(dlg) else {
        return;
    };
    let text = get_text(GetDlgItem(dlg, ID_SECRET));
    let (hint, code, error) = if text.trim().is_empty() {
        (
            "비밀키를 입력하면 현재 코드가 여기에 표시됩니다.".to_string(),
            String::new(),
            false,
        )
    } else {
        match parse_secret(&text) {
            Err(e) => (e, String::new(), true),
            Ok(parsed) => {
                if let (true, Some((name, algorithm, digits, period))) = (apply_link, &parsed.link)
                {
                    let index = match algorithm {
                        otp::Algorithm::Sha1 => 0,
                        otp::Algorithm::Sha256 => 1,
                        otp::Algorithm::Sha512 => 2,
                    };
                    SendMessageW(GetDlgItem(dlg, ID_ALGORITHM), CB_SETCURSEL, index, 0);
                    SendMessageW(
                        GetDlgItem(dlg, ID_DIGITS),
                        CB_SETCURSEL,
                        usize::from(*digits == 8),
                        0,
                    );
                    SendMessageW(
                        GetDlgItem(dlg, ID_PERIOD),
                        CB_SETCURSEL,
                        usize::from(*period == 60),
                        0,
                    );
                    let name_box = GetDlgItem(dlg, ID_NAME);
                    if get_text(name_box).trim().is_empty() && !name.is_empty() {
                        set(name_box, name);
                    }
                }
                let now = now_secs();
                match selected_params(dlg).and_then(|(algorithm, digits, period)| {
                    otp::totp(&parsed.secret.0, now, period, digits, algorithm)
                        .map(|c| (c, period - now % period))
                }) {
                    Ok((c, left)) => (
                        format!(
                            "현재 코드 · {left}초 남음 — 기존 인증 앱의 코드와 같은지 확인하세요."
                        ),
                        group_code(&c),
                        false,
                    ),
                    Err(e) => (e, String::new(), true),
                }
            }
        }
    };
    // A validation message from the last 추가 attempt stays until an input changes.
    let (hint, error) = match st.message.borrow().clone() {
        Some(message) if !error => (message, true),
        _ => (hint, error),
    };
    st.error.set(error);
    set_if_changed(GetDlgItem(dlg, ID_HINT), &hint);
    InvalidateRect(GetDlgItem(dlg, ID_HINT), null(), 1);
    set_if_changed(GetDlgItem(dlg, ID_CODE), &code);
}
unsafe fn add_confirm(dlg: H) {
    let Some(st) = dialog_state::<AddState>(dlg) else {
        return;
    };
    let fail = |message: &str, focus: i32| {
        *st.message.borrow_mut() = Some(message.to_string());
        update_preview(dlg, false);
        SetFocus(GetDlgItem(dlg, focus));
    };
    let name = get_text(GetDlgItem(dlg, ID_NAME)).trim().to_string();
    if name.is_empty() {
        return fail("계정 이름을 입력하세요.", ID_NAME);
    }
    if name.len() > 1024 {
        return fail("계정 이름이 너무 깁니다.", ID_NAME);
    }
    let text = get_text(GetDlgItem(dlg, ID_SECRET));
    if text.trim().is_empty() {
        return fail("비밀키를 입력하세요.", ID_SECRET);
    }
    let parsed = match parse_secret(&text) {
        Ok(parsed) => parsed,
        Err(e) => return fail(&e, ID_SECRET),
    };
    drop(text);
    let (algorithm, digits, period) = match selected_params(dlg) {
        Ok(params) => params,
        Err(e) => return fail(&e, ID_ALGORITHM),
    };
    let lower = name.to_lowercase();
    if st.names.iter().any(|n| n.to_lowercase() == lower)
        && MessageBoxW(
            dlg,
            wide("같은 이름의 계정이 이미 있습니다. 그래도 추가할까요?").as_ptr(),
            wide("계정 추가").as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        ) != IDYES
    {
        return;
    }
    *st.result.borrow_mut() = Some(Entry {
        name,
        secret: parsed.secret,
        algorithm,
        digits,
        period,
    });
    clear_edit(GetDlgItem(dlg, ID_SECRET));
    EndDialog(dlg, 1);
}
unsafe extern "system" fn add_proc(dlg: H, msg: u32, w: usize, l: isize) -> isize {
    match msg {
        WM_INITDIALOG => {
            init_dialog(dlg, l);
            for (id, values) in [
                (ID_ALGORITHM, &["SHA-1", "SHA-256", "SHA-512"][..]),
                (ID_DIGITS, &["6자리", "8자리"][..]),
                (ID_PERIOD, &["30초", "60초"][..]),
            ] {
                let combo = GetDlgItem(dlg, id);
                for v in values {
                    SendMessageW(combo, CB_ADDSTRING, 0, wide(v).as_ptr() as isize);
                }
                SendMessageW(combo, CB_SETCURSEL, 0, 0);
            }
            SendMessageW(GetDlgItem(dlg, ID_NAME), EM_LIMITTEXT, 256, 0);
            SendMessageW(GetDlgItem(dlg, ID_SECRET), EM_LIMITTEXT, 8192, 0);
            if let Some(st) = dialog_state::<AddState>(dlg) {
                let font = make_font(200, 700, "Consolas", GetDpiForWindow(dlg));
                st.font.set(font);
                SendMessageW(GetDlgItem(dlg, ID_CODE), WM_SETFONT, font as usize, 0);
            }
            SetTimer(dlg, 1, 500, null_mut());
            update_preview(dlg, false);
            1
        }
        WM_TIMER => {
            update_preview(dlg, false);
            1
        }
        WM_COMMAND => {
            touch();
            let (id, code) = ((w & 0xffff) as i32, (w >> 16) & 0xffff);
            let edited = matches!((id, code), (ID_NAME | ID_SECRET, EN_CHANGE))
                || matches!(
                    (id, code),
                    (ID_ALGORITHM | ID_DIGITS | ID_PERIOD, CBN_SELCHANGE)
                );
            if edited {
                if let Some(st) = dialog_state::<AddState>(dlg) {
                    st.message.borrow_mut().take();
                }
            }
            match id {
                ID_SECRET if code == EN_CHANGE => update_preview(dlg, true),
                ID_NAME if code == EN_CHANGE => update_preview(dlg, false),
                ID_ALGORITHM | ID_DIGITS | ID_PERIOD if code == CBN_SELCHANGE => {
                    update_preview(dlg, false)
                }
                1 => add_confirm(dlg),
                2 => {
                    clear_edit(GetDlgItem(dlg, ID_SECRET));
                    EndDialog(dlg, 0);
                }
                _ => {}
            }
            1
        }
        WM_CTLCOLORSTATIC => {
            let error = dialog_state::<AddState>(dlg).is_some_and(|s| s.error.get());
            let color = match GetDlgCtrlID(l as H) {
                ID_HINT if error => RED,
                ID_HINT | ID_NOTE => GRAY,
                ID_CODE => ACCENT,
                _ => TEXT,
            };
            static_color(w as H, color)
        }
        WM_DESTROY => {
            clear_edit(GetDlgItem(dlg, ID_SECRET));
            KillTimer(dlg, 1);
            if let Some(st) = dialog_state::<AddState>(dlg) {
                let font = st.font.replace(null_mut());
                if !font.is_null() {
                    DeleteObject(font);
                }
            }
            ui(|u| u.dialog.set(null_mut()));
            0
        }
        _ => 0,
    }
}
unsafe fn run_add_dialog(owner: H, names: Vec<String>) -> Option<Entry> {
    let label = SS_NOPREFIX;
    let input = WS_BORDER | ES_AUTOHSCROLL;
    let combo = CBS_DROPDOWNLIST | WS_VSCROLL;
    let mut t = Template::new("계정 추가", 256, 206);
    t.item(STATIC, "계정 이름", label, 10, 9, 236, 9, -1);
    t.item(EDIT, "", input, 10, 20, 236, 14, ID_NAME);
    t.item(
        STATIC,
        "비밀키 (Base32 또는 otpauth:// 링크)",
        label,
        10,
        41,
        236,
        9,
        -1,
    );
    t.item(EDIT, "", input | ES_PASSWORD, 10, 52, 236, 14, ID_SECRET);
    t.item(STATIC, "알고리즘", label, 10, 73, 76, 9, -1);
    t.item(STATIC, "자릿수", label, 90, 73, 76, 9, -1);
    t.item(STATIC, "주기", label, 170, 73, 76, 9, -1);
    t.item(COMBOBOX, "", combo, 10, 84, 76, 80, ID_ALGORITHM);
    t.item(COMBOBOX, "", combo, 90, 84, 76, 80, ID_DIGITS);
    t.item(COMBOBOX, "", combo, 170, 84, 76, 80, ID_PERIOD);
    t.item(STATIC, "", label, 10, 108, 236, 18, ID_HINT);
    t.item(STATIC, "", label, 10, 127, 236, 20, ID_CODE);
    t.item(
        STATIC,
        "저장한 비밀키는 이 앱에서 다시 보거나 내보낼 수 없습니다. 원본은 별도의 안전한 곳에 보관하세요.",
        label,
        10,
        152,
        236,
        18,
        ID_NOTE,
    );
    t.item(
        BUTTON,
        "추가",
        BS_DEFPUSHBUTTON,
        140,
        182,
        50,
        15,
        IDOK as i32,
    );
    t.item(BUTTON, "취소", 0, 196, 182, 50, 15, IDCANCEL as i32);
    let state = AddState {
        names,
        result: RefCell::new(None),
        font: Cell::new(null_mut()),
        error: Cell::new(false),
        message: RefCell::new(None),
    };
    t.run(owner, add_proc, &state as *const AddState as isize);
    state.result.into_inner()
}

struct ConfirmState {
    message: String,
    result: RefCell<Option<SecretText>>,
}
unsafe extern "system" fn confirm_proc(dlg: H, msg: u32, w: usize, l: isize) -> isize {
    match msg {
        WM_INITDIALOG => {
            init_dialog(dlg, l);
            if let Some(st) = dialog_state::<ConfirmState>(dlg) {
                set(GetDlgItem(dlg, ID_MESSAGE), &st.message);
            }
            let password = GetDlgItem(dlg, ID_PASSWORD);
            SendMessageW(password, EM_LIMITTEXT, 1024, 0);
            SetFocus(password);
            0
        }
        WM_COMMAND => {
            touch();
            let password = GetDlgItem(dlg, ID_PASSWORD);
            match w & 0xffff {
                IDOK => {
                    let text = get_text(password);
                    if text.is_empty() {
                        SetFocus(password);
                        return 1;
                    }
                    if let Some(st) = dialog_state::<ConfirmState>(dlg) {
                        *st.result.borrow_mut() = Some(text);
                    }
                    clear_edit(password);
                    EndDialog(dlg, 1);
                }
                IDCANCEL => {
                    clear_edit(password);
                    EndDialog(dlg, 0);
                }
                _ => {}
            }
            1
        }
        WM_CTLCOLORSTATIC => static_color(
            w as H,
            if GetDlgCtrlID(l as H) == ID_MESSAGE {
                RED
            } else {
                TEXT
            },
        ),
        WM_DESTROY => {
            clear_edit(GetDlgItem(dlg, ID_PASSWORD));
            ui(|u| u.dialog.set(null_mut()));
            0
        }
        _ => 0,
    }
}
unsafe fn run_confirm_dialog(owner: H, name: &str) -> Option<SecretText> {
    let mut t = Template::new("계정 삭제", 244, 108);
    t.item(STATIC, "", SS_NOPREFIX, 10, 9, 224, 34, ID_MESSAGE);
    t.item(STATIC, "보관함 비밀번호", SS_NOPREFIX, 10, 48, 224, 9, -1);
    t.item(
        EDIT,
        "",
        WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD,
        10,
        59,
        224,
        14,
        ID_PASSWORD,
    );
    t.item(
        BUTTON,
        "삭제",
        BS_DEFPUSHBUTTON,
        128,
        84,
        50,
        15,
        IDOK as i32,
    );
    t.item(BUTTON, "취소", 0, 184, 84, 50, 15, IDCANCEL as i32);
    // Shorten long names so the warning itself is never clipped.
    let shown: String = if name.chars().count() > 40 {
        name.chars().take(39).chain(Some('…')).collect()
    } else {
        name.to_string()
    };
    let state = ConfirmState {
        message: format!(
            "‘{shown}’ 계정을 이 PC에서 영구 삭제합니다.\n원본 시크릿키가 없으면 다시 등록할 수 없습니다. 계속하려면 비밀번호를 입력하세요."
        ),
        result: RefCell::new(None),
    };
    t.run(owner, confirm_proc, &state as *const ConfirmState as isize);
    state.result.into_inner()
}

// ---------------------------------------------------------------------------
// Main window.

unsafe fn fill(dc: H, r: &Rect, color: u32) {
    let brush = CreateSolidBrush(color);
    FillRect(dc, r, brush);
    DeleteObject(brush);
}
unsafe fn draw_text(dc: H, text: &str, mut r: Rect, font: H, color: u32, format: u32) {
    let old = SelectObject(dc, font);
    SetTextColor(dc, color);
    DrawTextW(dc, wide(text).as_ptr(), -1, &mut r, format);
    SelectObject(dc, old);
}
unsafe fn draw_row(d: &DrawItem) {
    const DT_RIGHT: u32 = 0x02;
    const DT_VCENTER: u32 = 0x04;
    const DT_SINGLELINE: u32 = 0x20;
    const DT_NOPREFIX: u32 = 0x800;
    const DT_END_ELLIPSIS: u32 = 0x8000;
    const LINE_FORMAT: u32 = DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS;
    if d.ctl_type != 2 {
        return; // ODT_LISTBOX
    }
    let (dc, r) = (d.dc, d.rc);
    fill(dc, &r, if d.state & 1 != 0 { SELECTED } else { WHITE });
    fill(
        dc,
        &Rect {
            left: r.left + sc(12),
            top: r.bottom - 1,
            right: r.right - sc(12),
            bottom: r.bottom,
        },
        LINE,
    );
    ROWS.with(|rows| {
        let Ok(rows) = rows.try_borrow() else { return };
        let Some(row) = rows.get(d.item_id as usize) else {
            return;
        };
        SetBkMode(dc, 1);
        let pad = sc(16);
        let right_w = sc(150);
        let seconds_w = sc(36);
        let urgent = row.remaining <= 5;
        let text_right = r.right - pad - right_w - sc(8);
        let (bold, small, code_font) = ui(|u| (u.bold.get(), u.small.get(), u.code.get()));
        draw_text(
            dc,
            &row.name,
            Rect {
                left: r.left + pad,
                top: r.top + sc(8),
                right: text_right,
                bottom: r.top + sc(34),
            },
            bold,
            TEXT,
            LINE_FORMAT,
        );
        draw_text(
            dc,
            &row.meta,
            Rect {
                left: r.left + pad,
                top: r.top + sc(34),
                right: text_right,
                bottom: r.top + sc(54),
            },
            small,
            GRAY,
            LINE_FORMAT,
        );
        draw_text(
            dc,
            &row.code,
            Rect {
                left: r.right - pad - right_w,
                top: r.top + sc(4),
                right: r.right - pad,
                bottom: r.top + sc(40),
            },
            code_font,
            if urgent { RED } else { TEXT },
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
        );
        draw_text(
            dc,
            &format!("{}초", row.remaining),
            Rect {
                left: r.right - pad - seconds_w,
                top: r.top + sc(39),
                right: r.right - pad,
                bottom: r.top + sc(57),
            },
            small,
            if urgent { RED } else { GRAY },
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
        );
        let bar = Rect {
            left: r.right - pad - right_w + sc(40),
            top: r.top + sc(46),
            right: r.right - pad - seconds_w - sc(6),
            bottom: r.top + sc(46) + sc(4).max(3),
        };
        fill(dc, &bar, LINE);
        let filled =
            i64::from(bar.right - bar.left) * row.remaining as i64 / row.period.max(1) as i64;
        fill(
            dc,
            &Rect {
                right: bar.left + filled as i32,
                ..bar
            },
            if urgent { RED } else { ACCENT },
        );
    });
}
unsafe fn ctl_color(dc: H, ctl: H) -> isize {
    let color = match GetDlgCtrlID(ctl) as usize {
        ID_SUBTITLE | ID_STATUS | ID_EMPTY => GRAY,
        ID_CAPS => ORANGE,
        ID_INFO if ui(|u| u.warn_info.get()) => RED,
        ID_INFO => GRAY,
        _ => TEXT,
    };
    SetTextColor(dc, color);
    SetBkMode(dc, 1);
    GetStockObject(0) as isize // WHITE_BRUSH, the window background
}
unsafe fn create(hwnd: H) -> isize {
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        notice(hwnd, "LOCALAPPDATA 경로가 없습니다.");
        return -1;
    };
    let path = PathBuf::from(base).join("LocalOtp").join("vault.bin");
    if let Err(e) = fs::create_dir_all(path.parent().unwrap()) {
        notice(hwnd, &format!("보관함 폴더 생성 실패: {e}"));
        return -1;
    }
    // The lock file contains no vault data; the exclusive handle prevents two
    // instances (also in other sessions) from overwriting each other's changes.
    let handle = CreateFileW(
        path_wide(&path.with_file_name("vault.lock")).as_ptr(),
        0xc000_0000,
        0,
        null_mut(),
        4,
        0x80,
        null_mut(),
    );
    if handle as isize == -1 {
        notice(
            hwnd,
            "보관함을 잠글 수 없습니다. Local OTP가 이미 실행 중인지 확인하세요.",
        );
        return -1;
    }
    let lock = OwnedHandle(handle);
    delete_fonts(create_fonts(GetDpiForWindow(hwnd).max(96)));
    let edit = WS_EX_CLIENTEDGE;
    let label = SS_NOPREFIX;
    let c = Controls {
        title: control(hwnd, "STATIC", "Local OTP", label, 0, ID_TITLE),
        subtitle: control(hwnd, "STATIC", "", label, 0, ID_SUBTITLE),
        pass_label: control(hwnd, "STATIC", "비밀번호", label, 0, ID_PASS_LABEL),
        pass: control(
            hwnd,
            "EDIT",
            "",
            ES_PASSWORD | ES_AUTOHSCROLL,
            edit,
            ID_PASS,
        ),
        confirm_label: control(hwnd, "STATIC", "비밀번호 확인", label, 0, ID_CONFIRM_LABEL),
        confirm: control(
            hwnd,
            "EDIT",
            "",
            ES_PASSWORD | ES_AUTOHSCROLL,
            edit,
            ID_CONFIRM,
        ),
        caps: control(hwnd, "STATIC", "", label, 0, ID_CAPS),
        unlock: control(hwnd, "BUTTON", "잠금 해제", BS_DEFPUSHBUTTON, 0, ID_UNLOCK),
        info: control(hwnd, "STATIC", "", label, 0, ID_INFO),
        search: control(hwnd, "EDIT", "", ES_AUTOHSCROLL, edit, ID_SEARCH),
        lock: control(hwnd, "BUTTON", "잠그기", 0, 0, ID_LOCK),
        list: control(
            hwnd,
            "LISTBOX",
            "",
            LBS_NOTIFY | LBS_OWNERDRAWFIXED | LBS_NOINTEGRALHEIGHT | WS_VSCROLL,
            edit,
            ID_LIST,
        ),
        empty: control(hwnd, "STATIC", "", label | SS_CENTER, 0, ID_EMPTY),
        copy: control(hwnd, "BUTTON", "코드 복사", 0, 0, ID_COPY),
        add: control(hwnd, "BUTTON", "계정 추가…", 0, 0, ID_ADD),
        delete: control(hwnd, "BUTTON", "삭제…", 0, 0, ID_DELETE),
        status: control(hwnd, "STATIC", "", label | SS_ENDELLIPSIS, 0, ID_STATUS),
    };
    for (h, limit) in [(c.pass, 1024), (c.confirm, 1024), (c.search, 128)] {
        SendMessageW(h, EM_LIMITTEXT, limit, 0);
    }
    SendMessageW(
        c.search,
        EM_SETCUEBANNER,
        1,
        wide("계정 검색 (Ctrl+F)").as_ptr() as isize,
    );
    apply_fonts(&c);
    let mut app = App {
        hwnd,
        _lock: lock,
        path,
        c,
        session: None,
        generation: 0,
        new_vault: false,
        last_activity: Instant::now(),
        visible: Vec::new(),
        filter: String::new(),
        focus: null_mut(),
        clipboard: None,
        status: None,
        last_second: 0,
        lock_reason: LOCKED,
    };
    show_page(&mut app);
    APP.with(|cell| *cell.borrow_mut() = Some(app));
    SetTimer(hwnd, TIMER_TICK, 250, null_mut());
    protect_window(hwnd);
    if WTSRegisterSessionNotification(hwnd, 0) == 0 {
        notice(
            hwnd,
            "Windows 세션 잠금 알림을 등록하지 못했습니다. 5분 유휴 잠금은 계속 동작합니다.",
        );
    }
    0
}
unsafe fn destroy(hwnd: H) {
    WTSUnRegisterSessionNotification(hwnd);
    KillTimer(hwnd, TIMER_TICK);
    let app = APP.with(|cell| cell.try_borrow_mut().ok().and_then(|mut g| g.take()));
    if let Some(mut a) = app {
        a.session = None;
        clear_our_clipboard(&mut a);
    }
    ROWS.with(|r| {
        if let Ok(mut r) = r.try_borrow_mut() {
            r.clear()
        }
    });
    delete_fonts(ui(|u| {
        [&u.font, &u.bold, &u.small, &u.title, &u.code]
            .into_iter()
            .map(|cell| cell.replace(null_mut()))
            .filter(|f| !f.is_null())
            .collect()
    }));
    PostQuitMessage(0);
}
unsafe fn command(hwnd: H, w: usize) {
    let (id, code) = (w & 0xffff, (w >> 16) & 0xffff);
    match (id, code) {
        (ID_PASS | ID_CONFIRM, EN_CHANGE) => {
            with_app(|a| update_caps(a));
        }
        (ID_SEARCH, EN_CHANGE) => {
            with_app(|a| {
                let keep = selected_entry(a);
                a.filter = get_text(a.c.search).to_string();
                sync_list(a, keep);
            });
        }
        (ID_LIST, LBN_SELCHANGE) => {
            with_app(|a| update_buttons(a));
        }
        (ID_LIST, LBN_DBLCLK) | (ID_COPY, BN_CLICKED) => {
            if let Some(Err(e)) = with_app(|a| copy_selected(a)) {
                notice(hwnd, &e);
            }
        }
        (ID_UNLOCK, BN_CLICKED) => unlock(hwnd),
        (ID_LOCK, BN_CLICKED) => request_lock(LOCKED),
        (ID_ADD, BN_CLICKED) => add_account(hwnd),
        (ID_DELETE, BN_CLICKED) => delete_account(hwnd),
        (IDOK, _) => {
            if with_app(|a| a.session.is_none()).unwrap_or(false) {
                unlock(hwnd);
            } else if let Some(Some(Err(e))) =
                with_app(|a| selected_entry(a).map(|_| copy_selected(a)))
            {
                notice(hwnd, &e); // Enter with nothing selected does nothing.
            }
        }
        (IDCANCEL, _) => {
            with_app(|a| {
                if a.session.is_some() && !a.filter.is_empty() {
                    let keep = selected_entry(a);
                    a.filter.clear();
                    clear_edit(a.c.search);
                    sync_list(a, keep);
                }
            });
        }
        (ID_FOCUS_SEARCH, _) => {
            with_app(|a| {
                if a.session.is_some() {
                    SetFocus(a.c.search);
                    SendMessageW(a.c.search, EM_SETSEL, 0, -1);
                }
            });
        }
        _ => {}
    }
}
unsafe fn handle(hwnd: H, msg: u32, w: usize, l: isize) -> isize {
    match msg {
        WM_CREATE => create(hwnd),
        WM_SIZE => {
            with_app(|a| layout(a));
            0
        }
        WM_GETMINMAXINFO => {
            let info = &mut *(l as *mut MinMaxInfo);
            info.min_track = Point {
                x: sc(380),
                y: sc(500),
            };
            0
        }
        WM_DPICHANGED => {
            let old = create_fonts((w & 0xffff) as u32);
            let applied = with_app(|a| {
                apply_fonts(&a.c);
                SendMessageW(a.c.list, LB_SETITEMHEIGHT, 0, row_height() as isize);
            });
            if applied.is_some() {
                delete_fonts(old); // Only once no control still uses them.
            }
            let r = &*(l as *const Rect);
            SetWindowPos(
                hwnd,
                null_mut(),
                r.left,
                r.top,
                r.right - r.left,
                r.bottom - r.top,
                0x0004 | 0x0010,
            );
            0
        }
        WM_ACTIVATE => {
            if w & 0xffff == 0 {
                with_app(|a| {
                    let focus = GetFocus();
                    if IsChild(hwnd, focus) != 0 {
                        a.focus = focus;
                    }
                });
            }
            DefWindowProcW(hwnd, msg, w, l)
        }
        WM_SETFOCUS => {
            with_app(|a| {
                let saved = a.focus;
                let target = if !saved.is_null()
                    && IsWindowVisible(saved) != 0
                    && IsWindowEnabled(saved) != 0
                {
                    saved
                } else {
                    default_focus(a)
                };
                SetFocus(target);
            });
            0
        }
        WM_MEASUREITEM => {
            (*(l as *mut MeasureItem)).height = row_height() as u32;
            1
        }
        WM_DRAWITEM => {
            draw_row(&*(l as *const DrawItem));
            1
        }
        WM_CTLCOLORSTATIC => ctl_color(w as H, l as H),
        WM_COMMAND => {
            command(hwnd, w);
            0
        }
        WM_TIMER => {
            if w == TIMER_TICK {
                tick();
            }
            0
        }
        WM_WTSSESSION_CHANGE
            if matches!(
                w,
                WTS_SESSION_LOCK
                    | WTS_SESSION_LOGOFF
                    | WTS_CONSOLE_DISCONNECT
                    | WTS_REMOTE_DISCONNECT
            ) =>
        {
            request_lock(LOCKED_SESSION);
            0
        }
        WM_POWERBROADCAST if w == PBT_APMSUSPEND => {
            request_lock(LOCKED_SESSION);
            1
        }
        WM_ENDSESSION if w != 0 => {
            request_lock(LOCKED_SESSION);
            0
        }
        WM_DESTROY => {
            destroy(hwnd);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}
unsafe extern "system" fn wndproc(hwnd: H, msg: u32, w: usize, l: isize) -> isize {
    let result = handle(hwnd, msg, w, l);
    // A lock requested while the state was borrowed runs as soon as it is free.
    if let Some(reason) = ui(|u| u.pending_lock.get()) {
        if lock_now(reason) {
            ui(|u| u.pending_lock.set(None));
        }
    }
    result
}
/// Keyboard shortcuts for the main window. Returns true when handled.
unsafe fn shortcut(hwnd: H, msg: &Msg) -> bool {
    let Some((list, search, unlocked)) = with_app(|a| (a.c.list, a.c.search, a.session.is_some()))
    else {
        return false;
    };
    // AltGr is reported as Ctrl+Alt: never treat it as a Ctrl shortcut, or
    // typing characters such as ł or ń into a password field would trigger one.
    if GetKeyState(0x12) < 0 {
        return false; // VK_MENU (Alt) held
    }
    if !unlocked {
        return false; // Ctrl+L while locked would only wipe the typed password.
    }
    let ctrl = GetKeyState(0x11) < 0;
    let key = msg.wparam as i32;
    let id = match (ctrl, key) {
        (true, 0x4C) => ID_LOCK,                        // Ctrl+L
        (true, 0x46) => ID_FOCUS_SEARCH,                // Ctrl+F
        (true, 0x4E) => ID_ADD,                         // Ctrl+N
        (true, 0x43) if msg.hwnd == list => ID_COPY,    // Ctrl+C
        (false, 0x2E) if msg.hwnd == list => ID_DELETE, // Delete
        (false, 0x28) if msg.hwnd == search && IsWindowVisible(list) != 0 => {
            // Down arrow moves from the search box into the list.
            SetFocus(list);
            return true;
        }
        _ => return false,
    };
    PostMessageW(hwnd, WM_COMMAND, id, 0);
    true
}
fn main() {
    unsafe {
        let class = wide("LocalOtpWindow");
        // One instance per Windows session; the vault lock file additionally
        // covers other sessions of the same user.
        let mutex = CreateMutexW(
            null_mut(),
            0,
            wide("Local\\LocalOtp.SingleInstance.v1").as_ptr(),
        );
        if mutex.is_null() {
            notice(null_mut(), "앱 실행 잠금을 만들 수 없습니다.");
            return;
        }
        let already_exists = GetLastError() == 183;
        let _mutex = OwnedHandle(mutex);
        if already_exists {
            let existing = FindWindowW(class.as_ptr(), null());
            if existing.is_null() {
                notice(null_mut(), "Local OTP가 이미 실행 중입니다.");
            } else {
                if IsIconic(existing) != 0 {
                    ShowWindow(existing, 9); // SW_RESTORE
                }
                SetForegroundWindow(existing);
            }
            return;
        }
        InitCommonControlsEx(&InitCommonControls {
            size: 8,
            classes: 0x4000, // ICC_STANDARD_CLASSES
        });
        let instance = GetModuleHandleW(null());
        let wc = WndClass {
            style: 0,
            proc: Some(wndproc),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon: LoadIconW(instance, std::ptr::without_provenance::<u16>(1)),
            cursor: LoadCursorW(null_mut(), 32512usize as *const u16),
            background: GetStockObject(0),
            menu: null(),
            name: class.as_ptr(),
        };
        if RegisterClassW(&wc) == 0 {
            return;
        }
        let dpi = GetDpiForSystem().max(96) as i32;
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            wide("Local OTP").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            0x80000000u32 as i32,
            0x80000000u32 as i32,
            MulDiv(480, dpi, 96),
            MulDiv(640, dpi, 96),
            null_mut(),
            null_mut(),
            instance,
            null_mut(),
        );
        if hwnd.is_null() {
            return;
        }
        ShowWindow(hwnd, 1);
        UpdateWindow(hwnd);
        let mut msg: Msg = zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            let ours = msg.hwnd == hwnd || IsChild(hwnd, msg.hwnd) != 0;
            if ours
                && matches!(
                    msg.message,
                    WM_KEYDOWN | WM_SYSKEYDOWN | WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MOUSEWHEEL
                )
            {
                touch();
            }
            if ours && msg.message == WM_KEYDOWN && shortcut(hwnd, &msg) {
                continue;
            }
            if IsDialogMessageW(hwnd, &mut msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(name: &str, secret: &[u8]) -> Entry {
        Entry {
            name: name.into(),
            secret: Secret(secret.to_vec()),
            algorithm: otp::Algorithm::Sha1,
            digits: 6,
            period: 30,
        }
    }
    #[test]
    fn serialization_roundtrip_and_rejects_truncation() {
        let entries = vec![entry("test", &[1, 2, 3]), entry("두번째", &[4; 20])];
        let d = Secret(serialize(&entries).unwrap());
        let v = deserialize(&d.0).unwrap();
        assert_eq!(v[0].name, "test");
        assert_eq!(v[0].secret.0, vec![1, 2, 3]);
        assert_eq!(v[1].name, "두번째");
        for n in 0..d.0.len() {
            assert!(deserialize(&d.0[..n]).is_err())
        }
        // Serializing a filtered view (as delete does) skips exactly one entry.
        let without_first = Secret(serialize(entries.iter().skip(1)).unwrap());
        let v = deserialize(&without_first.0).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "두번째");
        let empty = Secret(serialize(std::iter::empty::<&Entry>()).unwrap());
        assert!(deserialize(&empty.0).unwrap().is_empty());
    }
    #[test]
    fn legacy_v1_reads_with_original_defaults() {
        let mut bytes = b"LOTP0001".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(b"test");
        bytes.extend_from_slice(&[1, 2, 3]);
        let entry = deserialize(&bytes).unwrap().pop().unwrap();
        assert_eq!(entry.name, "test");
        assert_eq!(entry.algorithm, otp::Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
        assert_eq!(entry.secret.0, vec![1, 2, 3]);
        for n in 0..bytes.len() {
            assert!(deserialize(&bytes[..n]).is_err());
        }
    }
    #[test]
    fn v2_supports_settings_and_rejects_invalid_values() {
        for algorithm in [
            otp::Algorithm::Sha1,
            otp::Algorithm::Sha256,
            otp::Algorithm::Sha512,
        ] {
            for digits in [6, 8] {
                for period in [30, 60] {
                    let entry = Entry {
                        algorithm,
                        digits,
                        period,
                        ..entry("test", &[1, 2, 3])
                    };
                    let encoded = Secret(serialize(&[entry]).unwrap());
                    let decoded = deserialize(&encoded.0).unwrap();
                    assert_eq!(
                        (decoded[0].algorithm, decoded[0].digits, decoded[0].period),
                        (algorithm, digits, period)
                    );
                    for n in 0..encoded.0.len() {
                        assert!(deserialize(&encoded.0[..n]).is_err());
                    }
                    for (pos, bad) in [(20, 0), (20, 4), (21, 7), (22, 0), (22, 31)] {
                        let mut bad_bytes = encoded.0.clone();
                        bad_bytes[pos] = bad;
                        assert!(deserialize(&bad_bytes).is_err());
                        wipe(&mut bad_bytes);
                    }
                }
            }
        }
        assert!(serialize(&[entry("test", &[1; 4097])]).is_err());
        assert!(serialize(&[entry("", &[1])]).is_err());
    }
    #[test]
    fn vault_file_is_never_overwritten_unexpectedly() {
        let folder = std::env::temp_dir().join(format!(
            "local-otp-synthetic-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&folder).unwrap();
        let path = folder.join("vault.bin");
        write_vault(&path, b"first", None).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::write(&path, b"newer data").unwrap();
        assert!(write_vault(&path, b"replacement", Some(b"old data")).is_err());
        assert!(write_vault(&path, b"replacement", None).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"newer data");
        write_vault(&path, b"replacement", Some(b"newer data")).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(
            fs::read_dir(&folder).unwrap().count(),
            1,
            "temporary file left"
        );
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&folder).unwrap();
    }
    #[test]
    fn secret_input_accepts_base32_and_links() {
        let p = parse_secret("  jbsw y3dp-ehpk 3pxp ").unwrap();
        assert_eq!(p.secret.0, b"Hello!\xde\xad\xbe\xef");
        assert!(p.link.is_none());
        let p = parse_secret(
            "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA512&digits=8&period=60",
        )
        .unwrap();
        let (name, algorithm, digits, period) = p.link.unwrap();
        assert_eq!(name, "GitHub:me");
        assert_eq!((algorithm, digits, period), (otp::Algorithm::Sha512, 8, 60));
        assert!(parse_secret("otpauth://totp/x?secret=JBSWY3DP&digits=7").is_err());
        assert!(parse_secret("otpauth://totp/x?secret=JBSWY3DP&period=15").is_err());
        assert!(parse_secret("not base32!").is_err());
    }
    #[test]
    fn code_grouping() {
        assert_eq!(group_code("123456"), "123 456");
        assert_eq!(group_code("12345678"), "1234 5678");
    }
}
