#![cfg_attr(not(test), windows_subsystem = "windows")]
mod otp;
mod vault;

use std::{
    ffi::c_void,
    fs::{self, OpenOptions},
    io::{Read, Write},
    mem::zeroed,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type H = *mut c_void;
type Lresult = isize;
#[repr(C)]
struct Point {
    x: i32,
    y: i32,
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
    proc: Option<unsafe extern "system" fn(H, u32, usize, isize) -> Lresult>,
    cls_extra: i32,
    wnd_extra: i32,
    instance: H,
    icon: H,
    cursor: H,
    background: H,
    menu: *const u16,
    name: *const u16,
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
    fn TranslateMessage(m: *const Msg) -> i32;
    fn DispatchMessageW(m: *const Msg) -> isize;
    fn IsDialogMessageW(h: H, m: *mut Msg) -> i32;
    fn PostQuitMessage(code: i32);
    fn MessageBoxW(h: H, text: *const u16, title: *const u16, flags: u32) -> i32;
    fn SetWindowTextW(h: H, t: *const u16) -> i32;
    fn EnableWindow(h: H, enabled: i32) -> i32;
    fn GetWindowTextLengthW(h: H) -> i32;
    fn GetWindowTextW(h: H, t: *mut u16, n: i32) -> i32;
    fn SendMessageW(h: H, m: u32, w: usize, l: isize) -> isize;
    fn SetWindowLongPtrW(h: H, i: i32, v: isize) -> isize;
    fn GetWindowLongPtrW(h: H, i: i32) -> isize;
    fn SetTimer(h: H, id: usize, ms: u32, cb: H) -> usize;
    fn LoadCursorW(instance: H, name: *const u16) -> H;
    fn LoadIconW(instance: H, name: *const u16) -> H;
}
#[link(name = "gdi32")]
unsafe extern "system" {
    fn GetStockObject(index: i32) -> H;
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
}
static BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static DESTROY_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[link(name = "wtsapi32")]
unsafe extern "system" {
    fn WTSRegisterSessionNotification(window: H, flags: u32) -> i32;
    fn WTSUnRegisterSessionNotification(window: H) -> i32;
}
static LOCK_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
const WM_WTSSESSION_CHANGE: u32 = 0x02b1;
const WM_POWERBROADCAST: u32 = 0x0218;
const PBT_APMSUSPEND: usize = 4;
const WTS_CONSOLE_DISCONNECT: usize = 2;
const WTS_REMOTE_DISCONNECT: usize = 4;
const WTS_SESSION_LOGOFF: usize = 6;
const WTS_SESSION_LOCK: usize = 7;
const WM_CREATE: u32 = 1;
const WM_DESTROY: u32 = 2;
const WM_COMMAND: u32 = 0x111;
const WM_TIMER: u32 = 0x113;
const GWLP_USERDATA: i32 = -21;
const WS_CHILD: u32 = 0x40000000;
const WS_TABSTOP: u32 = 0x00010000;
const WM_SETFONT: u32 = 0x0030;
const EM_EMPTYUNDOBUFFER: u32 = 0x00cd;
const WS_VISIBLE: u32 = 0x10000000;
const WS_BORDER: u32 = 0x00800000;
const ES_PASSWORD: u32 = 0x20;
const WS_VSCROLL: u32 = 0x00200000;
const LB_RESETCONTENT: u32 = 0x184;
const LB_ADDSTRING: u32 = 0x180;
const LB_GETCURSEL: u32 = 0x188;
const LB_SETCURSEL: u32 = 0x186;
const CB_ADDSTRING: u32 = 0x143;
const CB_GETCURSEL: u32 = 0x147;
const CB_SETCURSEL: u32 = 0x14e;
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
struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0)
    }
}
struct Entry {
    name: String,
    secret: Secret,
    algorithm: otp::Algorithm,
    digits: u32,
    period: u64,
}
struct LockFile(H);
impl Drop for LockFile {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct App {
    _lock: LockFile,
    path: PathBuf,
    entries: Vec<Entry>,
    unlocked: bool,
    last_activity: Instant,
    pass: H,
    confirm: H,
    name: H,
    secret: H,
    algorithm: H,
    digits: H,
    period: H,
    add: H,
    delete: H,
    list: H,
    status: H,
    countdown: H,
}
#[allow(clippy::too_many_arguments)] // Win32 control creation requires these distinct fields.
unsafe fn control(
    parent: H,
    class: &str,
    text: &str,
    style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: usize,
) -> H {
    let keyboard = if matches!(class, "EDIT" | "BUTTON" | "LISTBOX" | "COMBOBOX") {
        WS_TABSTOP
    } else {
        0
    };
    let h = CreateWindowExW(
        0,
        wide(class).as_ptr(),
        wide(text).as_ptr(),
        WS_CHILD | WS_VISIBLE | keyboard | style,
        x,
        y,
        w,
        h,
        parent,
        id as H,
        GetModuleHandleW(null()),
        null_mut(),
    );
    if !h.is_null() {
        SendMessageW(h, WM_SETFONT, GetStockObject(17) as usize, 1);
    }
    h
}
unsafe fn set(h: H, s: &str) {
    SetWindowTextW(h, wide(s).as_ptr());
}
unsafe fn take(h: H) -> String {
    let n = GetWindowTextLengthW(h).clamp(0, 8192) as usize;
    let mut b = vec![0u16; n + 1];
    let got = GetWindowTextW(h, b.as_mut_ptr(), (n + 1) as i32).max(0) as usize;
    set(h, "");
    SendMessageW(h, EM_EMPTYUNDOBUFFER, 0, 0);
    let s = String::from_utf16_lossy(&b[..got]);
    for v in &mut b {
        std::ptr::write_volatile(v, 0)
    }
    s
}
unsafe fn notice(h: H, s: &str) {
    MessageBoxW(h, wide(s).as_ptr(), wide("Local OTP").as_ptr(), 0x10);
}
fn serialize(entries: &[Entry]) -> Result<Vec<u8>, String> {
    if entries.len() > 1000 {
        return Err("계정이 너무 많습니다.".into());
    }
    // Allocate once so a resize never frees an earlier copy of plaintext keys.
    let mut size = 12usize;
    for entry in entries {
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
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let n = e.name.as_bytes();
        let s = &e.secret.0;
        if n.is_empty() || n.len() > 1024 || s.is_empty() || s.len() > 4096 {
            return Err("계정 데이터 크기가 올바르지 않습니다.".into());
        }
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
    const LIMIT: u64 = 16 * 1024 * 1024;
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
fn read_vault_with_blob(path: &Path, password: &str) -> Result<(Vec<Entry>, Vec<u8>), String> {
    let blob = read_vault_bytes(path)?;
    let plaintext = Secret(vault::decrypt(password, &blob)?);
    Ok((deserialize(&plaintext.0)?, blob))
}
fn read_vault(path: &Path, password: &str) -> Result<Vec<Entry>, String> {
    read_vault_with_blob(path, password).map(|(entries, _)| entries)
}
fn save(
    path: &Path,
    password: &str,
    entries: &[Entry],
    expected: Option<&[u8]>,
) -> Result<(), String> {
    let parent = path.parent().ok_or("저장 위치 오류")?;
    fs::create_dir_all(parent).map_err(|e| format!("폴더 생성 실패: {e}"))?;
    // Never replace an existing vault with newly initialized data.
    if expected.is_none() && path.exists() {
        return Err("기존 보관함이 있어 새로 만들 수 없습니다.".into());
    }
    let plain = Secret(serialize(entries)?);
    let ciphertext = match expected {
        None => vault::encrypt(password, &plain.0)?,
        Some(original) => {
            let current = read_vault_bytes(path)?;
            if current != original {
                return Err("보관함이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.".into());
            }
            vault::encrypt_existing(password, &plain.0, original)?
        }
    };
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
        f.write_all(&ciphertext)
            .map_err(|e| format!("저장 실패: {e}"))?;
        f.sync_all().map_err(|e| format!("동기화 실패: {e}"))?;
        drop(f);
        if let Some(original) = expected {
            let current = read_vault_bytes(path)?;
            if current != original {
                return Err("보관함이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.".into());
            }
        }
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
unsafe fn refresh(a: &App) {
    for h in [
        a.name,
        a.secret,
        a.algorithm,
        a.digits,
        a.period,
        a.add,
        a.delete,
    ] {
        EnableWindow(h, i32::from(a.unlocked));
    }
    let selected = SendMessageW(a.list, LB_GETCURSEL, 0, 0);
    SendMessageW(a.list, LB_RESETCONTENT, 0, 0);
    if a.unlocked {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        set(a.countdown, "코드 오른쪽에 계정별 남은 시간이 표시됩니다.");
        for e in &a.entries {
            let code = otp::totp(&e.secret.0, now, e.period, e.digits, e.algorithm)
                .unwrap_or_else(|_| "오류".into());
            let item = format!(
                "{}    {}    ({}초)",
                e.name,
                code,
                e.period - now % e.period
            );
            SendMessageW(a.list, LB_ADDSTRING, 0, wide(&item).as_ptr() as isize);
        }
        if selected >= 0 {
            SendMessageW(a.list, LB_SETCURSEL, selected as usize, 0);
        }
    } else {
        set(a.countdown, "");
    }
}
unsafe fn on_action(hwnd: H, a: &mut App, id: usize) {
    if id == 102 {
        a.last_activity = Instant::now();
        a.entries.clear();
        a.unlocked = false;
        for h in [a.pass, a.confirm, a.secret] {
            set(h, "");
            SendMessageW(h, EM_EMPTYUNDOBUFFER, 0, 0);
        }
        set(a.name, "");
        set(a.status, "잠김 — 비밀번호를 입력하고 열기를 누르세요.");
        refresh(a);
        return;
    }
    if id == 101 {
        let mut pass = take(a.pass);
        let mut confirm = take(a.confirm);
        if pass.is_empty() {
            notice(hwnd, "비밀번호를 입력하세요.");
            wipe_string(&mut pass);
            wipe_string(&mut confirm);
            return;
        }
        if a.path.exists() {
            match read_vault(&a.path, &pass) {
                Ok(entries) => {
                    a.entries = entries;
                    a.unlocked = true;
                    set(a.status, "열림 — 변경 시 비밀번호를 다시 입력하세요.");
                    refresh(a)
                }
                Err(e) => notice(
                    hwnd,
                    &format!("열기 실패: {e}\n기존 파일은 변경하지 않았습니다."),
                ),
            }
        } else if pass.chars().count() < 12 {
            notice(hwnd, "새 보관함은 12자 이상 비밀번호를 사용하세요.")
        } else if pass != confirm {
            notice(hwnd, "새 보관함의 비밀번호 확인이 일치하지 않습니다.")
        } else {
            match save(&a.path, &pass, &[], None) {
                Ok(()) => {
                    a.entries.clear();
                    a.unlocked = true;
                    set(
                        a.status,
                        "새 보관함을 만들었습니다. 변경 시 비밀번호를 입력하세요.",
                    );
                    refresh(a)
                }
                Err(e) => notice(hwnd, &format!("생성 실패: {e}")),
            }
        }
        wipe_string(&mut pass);
        wipe_string(&mut confirm);
        return;
    }
    if id != 103 && id != 104 {
        return;
    }
    if !a.unlocked {
        notice(hwnd, "먼저 보관함을 열어 주세요.");
        return;
    }
    let mut pass = take(a.pass);
    set(a.confirm, "");
    if pass.is_empty() {
        notice(hwnd, "변경하려면 비밀번호를 입력하세요.");
        return;
    }
    let result = (|| -> Result<(), String> {
        let (current, original_blob) = read_vault_with_blob(&a.path, &pass)?;
        let current_data = Secret(serialize(&current)?);
        let display_data = Secret(serialize(&a.entries)?);
        if current_data.0 != display_data.0 {
            return Err("보관함이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.".into());
        }
        let mut next = current;
        if id == 103 {
            let mut name = take(a.name);
            let mut input = take(a.secret);
            if name.trim().is_empty() {
                wipe_string(&mut input);
                return Err("계정 이름을 입력하세요.".into());
            }
            if name.len() > 1024 {
                wipe_string(&mut input);
                return Err("계정 이름이 너무 깁니다.".into());
            }
            let decoded = otp::decode_base32(&input);
            wipe_string(&mut input);
            let secret = Secret(decoded?);
            if secret.0.len() > 4096 {
                return Err("비밀키가 너무 깁니다.".into());
            }
            let algorithm = match SendMessageW(a.algorithm, CB_GETCURSEL, 0, 0) {
                0 => otp::Algorithm::Sha1,
                1 => otp::Algorithm::Sha256,
                2 => otp::Algorithm::Sha512,
                _ => return Err("OTP 알고리즘을 선택하세요.".into()),
            };
            let digits = match SendMessageW(a.digits, CB_GETCURSEL, 0, 0) {
                0 => 6,
                1 => 8,
                _ => return Err("OTP 자릿수를 선택하세요.".into()),
            };
            let period = match SendMessageW(a.period, CB_GETCURSEL, 0, 0) {
                0 => 30,
                1 => 60,
                _ => return Err("OTP 주기를 선택하세요.".into()),
            };
            name = name.trim().to_string();
            next.push(Entry {
                name,
                secret,
                algorithm,
                digits,
                period,
            });
        } else {
            let selected = SendMessageW(a.list, LB_GETCURSEL, 0, 0);
            if selected < 0 || selected as usize >= next.len() {
                return Err("삭제할 계정을 선택하세요.".into());
            }
            if MessageBoxW(hwnd,wide("선택한 계정을 이 PC에서 삭제할까요? 원래 비밀키가 없으면 다시 등록할 수 없습니다.").as_ptr(),wide("계정 삭제").as_ptr(),0x24)!=6{return Ok(())}
            next.remove(selected as usize);
        }
        // A modal confirmation can dispatch a session-lock or close event.
        // Never commit after either happened while the dialog was open.
        use std::sync::atomic::Ordering;
        if a.last_activity.elapsed() >= Duration::from_secs(300) {
            LOCK_PENDING.store(true, Ordering::SeqCst);
        }
        if LOCK_PENDING.load(Ordering::SeqCst) || DESTROY_PENDING.load(Ordering::SeqCst) {
            return Err("Windows 세션이 잠기거나 창이 닫혀 변경을 취소했습니다.".into());
        }
        save(&a.path, &pass, &next, Some(&original_blob))?;
        a.entries = next;
        refresh(a);
        Ok(())
    })();
    wipe_string(&mut pass);
    if let Err(e) = result {
        if !DESTROY_PENDING.load(std::sync::atomic::Ordering::SeqCst)
            && !LOCK_PENDING.load(std::sync::atomic::Ordering::SeqCst)
        {
            notice(
                hwnd,
                &format!("변경 실패: {e}\n이 앱은 변경 내용을 저장하지 않았습니다."),
            )
        }
    }
}
unsafe extern "system" fn proc(hwnd: H, msg: u32, w: usize, l: isize) -> isize {
    match msg {
        WM_CREATE => {
            let root = match std::env::var_os("LOCALAPPDATA") {
                Some(v) => PathBuf::from(v).join("LocalOtp").join("vault.bin"),
                None => {
                    notice(hwnd, "LOCALAPPDATA 경로가 없습니다.");
                    return -1;
                }
            };
            // The lock file contains no vault data; the exclusive handle prevents
            // two instances from validating and overwriting each other's changes.
            if let Err(e) = fs::create_dir_all(root.parent().unwrap()) {
                notice(hwnd, &format!("보관함 폴더 생성 실패: {e}"));
                return -1;
            }
            let lock_path = root.with_file_name("vault.lock");
            let handle = CreateFileW(
                path_wide(&lock_path).as_ptr(),
                0xc0000000,
                0,
                null_mut(),
                4,
                0x80,
                null_mut(),
            );
            if handle as isize == -1 {
                notice(
                    hwnd,
                    "보관함을 잠글 수 없습니다. 이미 실행 중인지 확인하세요.",
                );
                return -1;
            }
            let lock = LockFile(handle);
            control(hwnd, "STATIC", "비밀번호:", 0, 15, 16, 85, 22, 0);
            let pass = control(
                hwnd,
                "EDIT",
                "",
                WS_BORDER | ES_PASSWORD,
                100,
                12,
                210,
                24,
                0,
            );
            control(hwnd, "STATIC", "새 비밀번호 확인:", 0, 320, 16, 120, 22, 0);
            let confirm = control(
                hwnd,
                "EDIT",
                "",
                WS_BORDER | ES_PASSWORD,
                440,
                12,
                210,
                24,
                0,
            );
            control(
                hwnd,
                "BUTTON",
                "열기 / 새로 만들기",
                0,
                15,
                48,
                150,
                28,
                101,
            );
            control(hwnd, "BUTTON", "잠그기", 0, 175, 48, 90, 28, 102);
            let status = control(
                hwnd,
                "STATIC",
                "잠김 — 새 보관함은 비밀번호와 확인을 입력하세요.",
                0,
                15,
                84,
                630,
                25,
                0,
            );
            let list = control(
                hwnd,
                "LISTBOX",
                "",
                WS_BORDER | WS_VSCROLL | 1,
                15,
                112,
                635,
                230,
                0,
            );
            control(hwnd, "STATIC", "계정 이름:", 0, 15, 356, 80, 22, 0);
            let name = control(hwnd, "EDIT", "", WS_BORDER, 100, 352, 210, 25, 0);
            control(hwnd, "STATIC", "Base32 비밀키:", 0, 320, 356, 120, 22, 0);
            let secret = control(
                hwnd,
                "EDIT",
                "",
                WS_BORDER | ES_PASSWORD,
                440,
                352,
                210,
                25,
                0,
            );
            control(hwnd, "STATIC", "알고리즘:", 0, 15, 394, 75, 22, 0);
            let algorithm = control(
                hwnd,
                "COMBOBOX",
                "",
                3 | WS_VSCROLL,
                100,
                390,
                120,
                150,
                105,
            );
            for value in ["SHA-1", "SHA-256", "SHA-512"] {
                SendMessageW(algorithm, CB_ADDSTRING, 0, wide(value).as_ptr() as isize);
            }
            SendMessageW(algorithm, CB_SETCURSEL, 0, 0);
            control(hwnd, "STATIC", "자릿수:", 0, 240, 394, 65, 22, 0);
            let digits = control(hwnd, "COMBOBOX", "", 3 | WS_VSCROLL, 310, 390, 90, 120, 106);
            for value in ["6자리", "8자리"] {
                SendMessageW(digits, CB_ADDSTRING, 0, wide(value).as_ptr() as isize);
            }
            SendMessageW(digits, CB_SETCURSEL, 0, 0);
            control(hwnd, "STATIC", "주기:", 0, 420, 394, 55, 22, 0);
            let period = control(hwnd, "COMBOBOX", "", 3 | WS_VSCROLL, 475, 390, 90, 120, 107);
            for value in ["30초", "60초"] {
                SendMessageW(period, CB_ADDSTRING, 0, wide(value).as_ptr() as isize);
            }
            SendMessageW(period, CB_SETCURSEL, 0, 0);
            let add = control(hwnd, "BUTTON", "계정 추가", 0, 15, 430, 110, 28, 103);
            let delete = control(hwnd, "BUTTON", "선택 계정 삭제", 0, 135, 430, 140, 28, 104);
            // Never leave the secret field available before the vault is unlocked.
            for h in [name, secret, algorithm, digits, period, add, delete] {
                EnableWindow(h, 0);
            }
            control(
                hwnd,
                "STATIC",
                "설정은 서비스에서 제공한 값과 같아야 합니다. 5분 유휴 시 잠깁니다.",
                0,
                15,
                468,
                635,
                24,
                0,
            );
            let countdown = control(hwnd, "STATIC", "", 0, 15, 495, 635, 24, 0);
            let app = Box::new(App {
                _lock: lock,
                path: root,
                entries: Vec::new(),
                unlocked: false,
                last_activity: Instant::now(),
                pass,
                confirm,
                name,
                secret,
                algorithm,
                digits,
                period,
                add,
                delete,
                list,
                status,
                countdown,
            });
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(app) as isize);
            SetTimer(hwnd, 1, 1000, null_mut());
            if WTSRegisterSessionNotification(hwnd, 0) == 0 {
                notice(hwnd, "Windows 세션 잠금 알림을 등록하지 못했습니다. 5분 유휴 잠금은 계속 동작합니다.");
            }
            0
        }
        WM_WTSSESSION_CHANGE | WM_POWERBROADCAST
            if (msg == WM_WTSSESSION_CHANGE
                && matches!(
                    w,
                    WTS_SESSION_LOCK
                        | WTS_SESSION_LOGOFF
                        | WTS_CONSOLE_DISCONNECT
                        | WTS_REMOTE_DISCONNECT
                ))
                || (msg == WM_POWERBROADCAST && w == PBT_APMSUSPEND) =>
        {
            use std::sync::atomic::Ordering;
            // During a modal dialog defer locking until the active operation exits.
            if BUSY.load(Ordering::SeqCst) {
                LOCK_PENDING.store(true, Ordering::SeqCst);
                return 0;
            }
            BUSY.store(true, Ordering::SeqCst);
            let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
            if !p.is_null() {
                on_action(hwnd, &mut *p, 102);
            }
            BUSY.store(false, Ordering::SeqCst);
            if DESTROY_PENDING.swap(false, Ordering::SeqCst) {
                if !p.is_null() {
                    drop(Box::from_raw(p));
                }
                PostQuitMessage(0);
            }
            0
        }
        WM_COMMAND | WM_TIMER => {
            use std::sync::atomic::Ordering;
            // Native edit notifications and modal dialogs may synchronously
            // reenter the window procedure. Never borrow App twice.
            if BUSY.swap(true, Ordering::SeqCst) {
                return 0;
            }
            let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
            if !p.is_null() {
                if msg == WM_COMMAND {
                    (*p).last_activity = Instant::now();
                    on_action(hwnd, &mut *p, w & 0xffff);
                } else if (*p).last_activity.elapsed() >= Duration::from_secs(300) {
                    on_action(hwnd, &mut *p, 102);
                } else {
                    refresh(&*p);
                }
                if LOCK_PENDING.swap(false, Ordering::SeqCst) {
                    on_action(hwnd, &mut *p, 102);
                }
            }
            BUSY.store(false, Ordering::SeqCst);
            if DESTROY_PENDING.swap(false, Ordering::SeqCst) {
                if !p.is_null() {
                    drop(Box::from_raw(p));
                }
                PostQuitMessage(0);
            }
            0
        }
        WM_DESTROY => {
            use std::sync::atomic::Ordering;
            WTSUnRegisterSessionNotification(hwnd);
            let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
            if BUSY.load(Ordering::SeqCst) {
                DESTROY_PENDING.store(true, Ordering::SeqCst);
            } else {
                if !p.is_null() {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    drop(Box::from_raw(p));
                }
                PostQuitMessage(0);
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}
fn main() {
    unsafe {
        // A named machine-wide mutex prevents simultaneous processes, including
        // other sessions. Fail closed if it cannot be created or opened.
        let mutex = CreateMutexW(
            null_mut(),
            0,
            wide("Global\\LocalOtp.SingleInstance.v1").as_ptr(),
        );
        if mutex.is_null() {
            notice(null_mut(), "앱 실행 잠금을 만들 수 없습니다.");
            return;
        }
        let already_exists = GetLastError() == 183;
        let _mutex = LockFile(mutex);
        if already_exists {
            notice(null_mut(), "Local OTP가 이미 실행 중입니다.");
            return;
        }
        let instance = GetModuleHandleW(null());
        let class = wide("LocalOtpWindow");
        let wc = WndClass {
            style: 0,
            proc: Some(proc),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon: LoadIconW(instance, std::ptr::without_provenance::<u16>(1)),
            cursor: LoadCursorW(null_mut(), 32512usize as *const u16),
            background: 6usize as H,
            menu: null(),
            name: class.as_ptr(),
        };
        if RegisterClassW(&wc) == 0 {
            return;
        }
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            wide("Local OTP").as_ptr(),
            0x00ca0000,
            0x80000000u32 as i32,
            0x80000000u32 as i32,
            685,
            580,
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
    #[test]
    fn serialization_roundtrip_and_rejects_truncation() {
        let entries = vec![Entry {
            name: "test".into(),
            secret: Secret(vec![1, 2, 3]),
            algorithm: otp::Algorithm::Sha1,
            digits: 6,
            period: 30,
        }];
        let d = Secret(serialize(&entries).unwrap());
        let v = deserialize(&d.0).unwrap();
        assert_eq!(v[0].name, "test");
        assert_eq!(v[0].secret.0, vec![1, 2, 3]);
        for n in 0..d.0.len() {
            assert!(deserialize(&d.0[..n]).is_err())
        }
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
                        name: "test".into(),
                        secret: Secret(vec![1, 2, 3]),
                        algorithm,
                        digits,
                        period,
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
        let oversized = Entry {
            name: "test".into(),
            secret: Secret(vec![1; 4097]),
            algorithm: otp::Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        assert!(serialize(&[oversized]).is_err());
    }
    #[test]
    fn changed_original_never_overwritten_on_save() {
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
        fs::write(&path, b"newer data").unwrap();
        assert!(save(&path, "synthetic password", &[], Some(b"old data")).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"newer data");
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&folder).unwrap();
    }
}
