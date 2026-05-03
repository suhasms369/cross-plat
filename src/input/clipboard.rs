/// Clipboard sync — reads/writes local clipboard via platform CLI tools.
///
/// macOS  → pbcopy / pbpaste
/// Linux  → xclip (X11) or wl-clipboard (Wayland)
/// Windows→ PowerShell Get-Clipboard / Set-Clipboard
///
/// This avoids the arboard → image → moxcms → pxfm dependency chain.

use anyhow::Result;
use std::process::{Command, Stdio};
use std::io::Write;

pub struct Clipboard;

impl Clipboard {
    pub fn new() -> Result<Self> { Ok(Self) }

    pub fn get_text(&self) -> Option<String> {
        let output = platform_paste_cmd()?.output().ok()?;
        if output.status.success() {
            String::from_utf8(output.stdout).ok()
        } else {
            None
        }
    }

    pub fn set_text(&self, text: &str) -> Result<()> {
        let mut child = platform_copy_cmd()
            .ok_or_else(|| anyhow::anyhow!("No clipboard tool found"))?
            .stdin(Stdio::piped())
            .spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(text.as_bytes())?;
        }
        child.wait()?;
        Ok(())
    }
}

fn platform_paste_cmd() -> Option<Command> {
    #[cfg(target_os = "macos")]
    { return Some(Command::new("pbpaste")); }
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-Command", "Get-Clipboard"]);
        return Some(cmd);
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WAYLAND_DISPLAY").is_ok() {
            let mut cmd = Command::new("wl-paste");
            cmd.arg("--no-newline");
            return Some(cmd);
        }
        let mut cmd = Command::new("xclip");
        cmd.args(["-selection", "clipboard", "-o"]);
        return Some(cmd);
    }
    #[allow(unreachable_code)] None
}

fn platform_copy_cmd() -> Option<Command> {
    #[cfg(target_os = "macos")]
    { return Some(Command::new("pbcopy")); }
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-Command", "$input | Set-Clipboard"]);
        return Some(cmd);
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WAYLAND_DISPLAY").is_ok() {
            return Some(Command::new("wl-copy"));
        }
        let mut cmd = Command::new("xclip");
        cmd.args(["-selection", "clipboard"]);
        return Some(cmd);
    }
    #[allow(unreachable_code)] None
}

pub fn clipboard_changed(current: &Option<String>, last: &Option<String>) -> bool {
    current != last
}
