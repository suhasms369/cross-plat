use rdev::{Event, EventType, listen};
use tokio::sync::mpsc;
use std::thread;

use crate::network::protocol::DataMsg;

/// Starts a background thread that listens to all local input events
/// and converts them to DataMsg, sending them over the channel.
///
/// rdev::listen is blocking so it runs in a dedicated OS thread,
/// with events forwarded into the async world via an mpsc channel.
pub fn start_capture(tx: mpsc::Sender<DataMsg>) {
    thread::spawn(move || {
        listen(move |event: Event| {
            if let Some(msg) = event_to_datamsg(&event) {
                // try_send drops if channel full — acceptable for input events
                let _ = tx.blocking_send(msg);
            }
        })
        .expect("rdev listen failed");
    });
}

fn event_to_datamsg(event: &Event) -> Option<DataMsg> {
    match &event.event_type {
        EventType::MouseMove { x, y } => Some(DataMsg::MouseMove { x: *x, y: *y }),

        EventType::ButtonPress(btn) => Some(DataMsg::MouseButton {
            button: button_id(btn),
            pressed: true,
        }),
        EventType::ButtonRelease(btn) => Some(DataMsg::MouseButton {
            button: button_id(btn),
            pressed: false,
        }),

        EventType::Wheel { delta_x, delta_y } => Some(DataMsg::MouseScroll {
            delta_x: *delta_x as f64,
            delta_y: *delta_y as f64,
        }),

        EventType::KeyPress(key) => Some(DataMsg::KeyEvent {
            key_code: key_code(key),
            key_name: key_name(key),
            pressed: true,
        }),
        EventType::KeyRelease(key) => Some(DataMsg::KeyEvent {
            key_code: key_code(key),
            key_name: key_name(key),
            pressed: false,
        }),
    }
}

fn button_id(btn: &rdev::Button) -> u8 {
    match btn {
        rdev::Button::Left    => 0,
        rdev::Button::Right   => 1,
        rdev::Button::Middle  => 2,
        rdev::Button::Unknown(n) => *n as u8,
    }
}

fn key_code(key: &rdev::Key) -> u32 {
    // rdev provides a platform-independent Key enum.
    // We use debug string as a stable identifier for now;
    // a full mapping would be a large match block per OS.
    format!("{:?}", key).len() as u32 // placeholder — real impl maps Key → scancode
}

fn key_name(key: &rdev::Key) -> Option<String> {
    Some(format!("{:?}", key))
}
