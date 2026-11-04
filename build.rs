use std::{env, fs, path::PathBuf};

// Write the documented Windows .res format directly. This keeps the build free
// of resource-compiler crates and does not require rc.exe on the PATH.
fn u16le(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn word(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}
fn dword(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn align(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}
fn resource(out: &mut Vec<u8>, kind: u16, id: u16, data: &[u8]) {
    align(out);
    u32le(out, u32::try_from(data.len()).expect("resource too large"));
    u32le(out, 32); // Header size, including the two ordinal identifiers.
    u16le(out, 0xffff);
    u16le(out, kind);
    u16le(out, 0xffff);
    u16le(out, id);
    u32le(out, 0);
    u16le(out, 0x1030);
    u16le(out, 0x0409);
    u32le(out, 0);
    u32le(out, 0);
    out.extend_from_slice(data);
    align(out);
}
// Themed common controls (v6), per-monitor DPI awareness and no elevation.
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="LocalOtp" version="1.0.0.0"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=assets/local-otp.ico");
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
        return;
    }
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ENV").unwrap(),
        "msvc",
        "Windows icon resources require the MSVC target"
    );
    let ico = fs::read("assets/local-otp.ico").expect("could not read application icon");
    assert!(
        ico.len() >= 6 && word(&ico, 0) == 0 && word(&ico, 2) == 1,
        "invalid ICO header"
    );
    let count = word(&ico, 4) as usize;
    assert!(
        count > 0 && count <= (ico.len() - 6) / 16,
        "invalid ICO directory"
    );
    let mut res = Vec::new();
    resource(&mut res, 0, 0, &[]); // Required null resource header.
    let mut group = Vec::new();
    u16le(&mut group, 0);
    u16le(&mut group, 1);
    u16le(&mut group, count as u16);
    for i in 0..count {
        let entry = 6 + 16 * i;
        let len = dword(&ico, entry + 8) as usize;
        let offset = dword(&ico, entry + 12) as usize;
        assert!(
            len > 0
                && offset >= 6 + count * 16
                && offset.checked_add(len).is_some_and(|end| end <= ico.len()),
            "invalid ICO image bounds"
        );
        group.extend_from_slice(&ico[entry..entry + 12]);
        u16le(&mut group, (i + 1) as u16);
        resource(&mut res, 3, (i + 1) as u16, &ico[offset..offset + len]); // RT_ICON
    }
    resource(&mut res, 14, 1, &group); // RT_GROUP_ICON, ID 1
    resource(&mut res, 24, 1, MANIFEST.as_bytes()); // RT_MANIFEST, process manifest
    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("local-otp.res");
    fs::write(&path, res).expect("could not write icon resources");
    println!("cargo:rustc-link-arg-bin=local-otp={}", path.display());
}
