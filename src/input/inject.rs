use enigo::{Enigo, MouseControllable, KeyboardControllable};
use anyhow::Result;
use crate::network::protocol::DataMsg;

pub struct Injector {
    enigo: Enigo,
}

impl Injector {
    pub fn new() -> Result<Self> {
        Ok(Self { enigo: Enigo::new() })
    }

    pub fn inject(&mut self, msg: DataMsg) -> Result<()> {
        match msg {
            DataMsg::MouseMove { x, y } => {
                self.enigo.mouse_move_to(x as i32, y as i32);
            }
            DataMsg::MouseButton { button, pressed } => {
                use enigo::MouseButton::*;
                let btn = match button { 1 => Right, 2 => Middle, _ => Left };
                if pressed { self.enigo.mouse_down(btn); }
                else       { self.enigo.mouse_up(btn);   }
            }
            DataMsg::MouseScroll { delta_x: _, delta_y } => {
                self.enigo.mouse_scroll_y(delta_y as i32);
            }
            DataMsg::KeyEvent { key_name, pressed, .. } => {
                if let Some(name) = key_name {
                    if let Some(key) = name_to_enigo_key(&name) {
                        if pressed { self.enigo.key_down(key); }
                        else       { self.enigo.key_up(key);   }
                    }
                }
            }
            DataMsg::EdgeHandoff { .. } | DataMsg::EdgeReturn { .. } => {}
        }
        Ok(())
    }
}

fn name_to_enigo_key(name: &str) -> Option<enigo::Key> {
    use enigo::Key::*;
    match name {
        "Return" | "KpReturn"            => Some(Return),
        "Escape"                         => Some(Escape),
        "Tab"                            => Some(Tab),
        "Space"                          => Some(Space),
        "BackSpace"                      => Some(Backspace),
        "Delete"                         => Some(Delete),
        "ShiftLeft" | "ShiftRight"       => Some(Shift),
        "ControlLeft" | "ControlRight"   => Some(Control),
        "Alt" | "AltGr"                  => Some(Alt),
        "MetaLeft" | "MetaRight"         => Some(Meta),
        "CapsLock"                       => Some(CapsLock),
        "F1"  => Some(F1),  "F2"  => Some(F2),
        "F3"  => Some(F3),  "F4"  => Some(F4),
        "F5"  => Some(F5),  "F6"  => Some(F6),
        "F7"  => Some(F7),  "F8"  => Some(F8),
        "F9"  => Some(F9),  "F10" => Some(F10),
        "F11" => Some(F11), "F12" => Some(F12),
        "UpArrow"    => Some(UpArrow),
        "DownArrow"  => Some(DownArrow),
        "LeftArrow"  => Some(LeftArrow),
        "RightArrow" => Some(RightArrow),
        "Home"       => Some(Home),
        "End"        => Some(End),
        "PageUp"     => Some(PageUp),
        "PageDown"   => Some(PageDown),
        s => {
            let c = s.chars().next()?;
            if c.is_ascii_graphic() { Some(Layout(c)) } else { None }
        }
    }
}
