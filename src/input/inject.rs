use anyhow::Result;
use enigo::{
    Button, Direction, Enigo, Key, Keyboard, Mouse, Settings,
};
use crate::network::protocol::DataMsg;

pub struct Injector {
    enigo: Enigo,
}

impl Injector {
    pub fn new() -> Result<Self> {
        let enigo = Enigo::new(&Settings::default())
            .map_err(|e| anyhow::anyhow!("Enigo init failed: {}", e))?;
        Ok(Self { enigo })
    }

    pub fn inject(&mut self, msg: DataMsg) -> Result<()> {
        match msg {
            DataMsg::MouseMove { x, y } => {
                self.enigo.move_mouse(x as i32, y as i32, enigo::Coordinate::Abs)?;
            }
            DataMsg::MouseButton { button, pressed } => {
                let btn = match button { 2 => Button::Middle, 3 => Button::Right, _ => Button::Left };
                let dir = if pressed { Direction::Press } else { Direction::Release };
                self.enigo.button(btn, dir)?;
            }
            DataMsg::MouseScroll { delta_x, delta_y } => {
                if delta_y != 0.0 { self.enigo.scroll(delta_y as i32, enigo::Axis::Vertical)?; }
                if delta_x != 0.0 { self.enigo.scroll(delta_x as i32, enigo::Axis::Horizontal)?; }
            }
            DataMsg::KeyEvent { key_name, pressed, .. } => {
                if let Some(name) = key_name {
                    if let Some(key) = name_to_key(&name) {
                        let dir = if pressed { Direction::Press } else { Direction::Release };
                        self.enigo.key(key, dir)?;
                    }
                }
            }
            DataMsg::EdgeHandoff { .. } | DataMsg::EdgeReturn { .. } => {}
        }
        Ok(())
    }
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
        s => {
            let c = s.chars().next()?;
            if c.is_ascii_graphic() { Some(Key::Unicode(c)) } else { None }
        }
    }
}
