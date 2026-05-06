//! Input injection — runs on a dedicated OS thread because enigo::Enigo
//! holds a CGEventSource (macOS) which is !Send and cannot cross tokio task boundaries.
//!
//! Use `InjectorHandle` to send DataMsg from async code; the actual injection
//! happens on the thread that called `spawn_injector()`.

use std::sync::mpsc;
use std::thread;

use anyhow::Result;
use enigo::{Button, Direction, Enigo, Key, Keyboard, Mouse, Settings};

use crate::network::protocol::DataMsg;

// ── Public handle (Send + 'static) ───────────────────────────────────────────

#[derive(Clone)]
pub struct InjectorHandle {
    tx: mpsc::SyncSender<DataMsg>,
}

impl InjectorHandle {
    /// Non-blocking send — drops the event if the injector thread is busy.
    pub fn inject(&self, msg: DataMsg) {
        let _ = self.tx.try_send(msg);
    }
}

/// Spawns the injector on a dedicated OS thread.
/// Returns an `InjectorHandle` that is `Send + Clone` and safe to use from async code.
pub fn spawn_injector() -> Result<InjectorHandle> {
    let (tx, rx) = mpsc::sync_channel::<DataMsg>(256);

    thread::Builder::new()
        .name("meshkvm-injector".into())
        .spawn(move || {
            let mut enigo = match Enigo::new(&Settings::default()) {
                Ok(e)  => e,
                Err(e) => { eprintln!("[injector] init failed: {}", e); return; }
            };
            for msg in rx {
                if let Err(e) = inject_one(&mut enigo, msg) {
                    eprintln!("[injector] error: {}", e);
                }
            }
        })?;

    Ok(InjectorHandle { tx })
}

fn inject_one(enigo: &mut Enigo, msg: DataMsg) -> Result<()> {
    match msg {
        DataMsg::MouseMove { x, y } => {
            enigo.move_mouse(x as i32, y as i32, enigo::Coordinate::Abs)?;
        }
        DataMsg::MouseButton { button, pressed } => {
            let btn = match button { 2 => Button::Middle, 3 => Button::Right, _ => Button::Left };
            let dir = if pressed { Direction::Press } else { Direction::Release };
            enigo.button(btn, dir)?;
        }
        DataMsg::MouseScroll { delta_x, delta_y } => {
            if delta_y != 0.0 { enigo.scroll(delta_y as i32, enigo::Axis::Vertical)?; }
            if delta_x != 0.0 { enigo.scroll(delta_x as i32, enigo::Axis::Horizontal)?; }
        }
        DataMsg::KeyEvent { key_name, pressed, .. } => {
            if let Some(name) = key_name {
                if let Some(key) = name_to_key(&name) {
                    let dir = if pressed { Direction::Press } else { Direction::Release };
                    enigo.key(key, dir)?;
                }
            }
        }
        DataMsg::EdgeHandoff { .. } | DataMsg::EdgeReturn { .. } => {}
    }
    Ok(())
}

fn name_to_key(name: &str) -> Option<Key> {
    match name {
        "Return" | "KpReturn"          => Some(Key::Return),
        "Escape"                        => Some(Key::Escape),
        "Tab"                           => Some(Key::Tab),
        "Space"                         => Some(Key::Space),
        "BackSpace"                     => Some(Key::Backspace),
        "Delete"                        => Some(Key::Delete),
        "ShiftLeft" | "ShiftRight"      => Some(Key::Shift),
        "ControlLeft" | "ControlRight"  => Some(Key::Control),
        "Alt" | "AltGr"                 => Some(Key::Alt),
        "MetaLeft" | "MetaRight"        => Some(Key::Meta),
        "CapsLock"                      => Some(Key::CapsLock),
        "F1"  => Some(Key::F1),  "F2"  => Some(Key::F2),
        "F3"  => Some(Key::F3),  "F4"  => Some(Key::F4),
        "F5"  => Some(Key::F5),  "F6"  => Some(Key::F6),
        "F7"  => Some(Key::F7),  "F8"  => Some(Key::F8),
        "F9"  => Some(Key::F9),  "F10" => Some(Key::F10),
        "F11" => Some(Key::F11), "F12" => Some(Key::F12),
        "UpArrow"    => Some(Key::UpArrow),
        "DownArrow"  => Some(Key::DownArrow),
        "LeftArrow"  => Some(Key::LeftArrow),
        "RightArrow" => Some(Key::RightArrow),
        "Home"       => Some(Key::Home),
        "End"        => Some(Key::End),
        "PageUp"     => Some(Key::PageUp),
        "PageDown"   => Some(Key::PageDown),
        s => s.chars().next().filter(|c| c.is_ascii_graphic()).map(Key::Unicode),
    }
}

// Keep old Injector name as an alias so nothing else breaks
pub struct Injector;
impl Injector {
    pub fn new() -> Result<InjectorHandle> { spawn_injector() }
}
