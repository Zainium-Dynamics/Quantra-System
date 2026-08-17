//! Control server — JSON socket protocol + event broadcasting
//!
//! Same [4B LE length][JSON] framing as PID 1 `/run/quantra/control`.
//!
//! # Access control
//!
//! SO_PEERCRED check:
//! - uid=0 (root): full access — all commands
//! - uid=N (user): restricted access — own session queries only
//!
//! # Event subscription
//!
//! Send `{"cmd":"subscribe"}` → connection stays open, receives event JSON
//! objects as they occur. Used by COSMIC shell, session monitor tools.

use crate::dbus_bridge;
use crate::inhibitor::InhibitorManager;
use crate::power::PowerManager;
use crate::seat::SeatManager;
use crate::session::SessionManager;
use crate::types::*;
use crate::user::UserManager;
use crate::utmp;
use anyhow::Result;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

// ── Shared state ──────────────────────────────────────────────────────────────

pub type Sessions = Arc<Mutex<SessionManager>>;
pub type Users = Arc<Mutex<UserManager>>;
pub type Seats = Arc<Mutex<SeatManager>>;
pub type Inhibitors = Arc<Mutex<InhibitorManager>>;
pub type Power = Arc<Mutex<PowerManager>>;
pub type EventBus = Arc<RwLock<Vec<EventSink>>>;

#[allow(dead_code)]
pub struct EventSink {
    pub stream: UnixStream,
    pub uid: u32,
}

pub struct ControlServer {
    listener: UnixListener,
    sessions: Sessions,
    users: Users,
    seats: Seats,
    inhibitors: Inhibitors,
    power: Power,
    config: LogindConfig,
    event_bus: EventBus,
}

impl ControlServer {
    pub fn new(
        listener: UnixListener,
        sessions: Sessions,
        users: Users,
        seats: Seats,
        inhibitors: Inhibitors,
        power: Power,
        config: LogindConfig,
    ) -> Self {
        Self {
            listener,
            sessions,
            users,
            seats,
            inhibitors,
            power,
            config,
            event_bus: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn run(self) -> Result<()> {
        let Self {
            listener,
            sessions,
            users,
            seats,
            inhibitors,
            power,
            config,
            event_bus,
        } = self;

        // Spawn inhibitor GC thread
        {
            let inh = Arc::clone(&inhibitors);
            thread::Builder::new()
                .name("inhibitor-gc".into())
                .spawn(move || {
                    loop {
                        thread::sleep(Duration::from_secs(30));
                        inh.lock().unwrap().gc_dead_pids();
                    }
                })
                .ok();
        }

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let (peer_uid, peer_pid) = peer_cred(&stream);
                    log::debug!("Control client: uid={} pid={}", peer_uid, peer_pid);

                    let (s, u, se, i, p, cfg, eb) = (
                        Arc::clone(&sessions),
                        Arc::clone(&users),
                        Arc::clone(&seats),
                        Arc::clone(&inhibitors),
                        Arc::clone(&power),
                        config.clone(),
                        Arc::clone(&event_bus),
                    );
                    thread::spawn(move || {
                        if let Err(e) = handle(stream, peer_uid, peer_pid, s, u, se, i, p, cfg, eb)
                        {
                            log::debug!("Client: {}", e);
                        }
                    });
                }
                Err(e) => log::error!("accept: {}", e),
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn handle(
    mut stream: UnixStream,
    peer_uid: u32,
    _peer_pid: u32,
    sessions: Sessions,
    users: Users,
    seats: Seats,
    inhibitors: Inhibitors,
    power: Power,
    config: LogindConfig,
    event_bus: EventBus,
) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        if len > 1 << 20 {
            return Err(anyhow::anyhow!("request too large: {}", len));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;

        let req: Request = match serde_json::from_slice(&buf) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("JSON parse: {}", e));
                send_response(&mut stream, &resp)?;
                continue;
            }
        };

        // Subscribe mode — keep connection open and push events
        if let Request::Subscribe = req {
            stream.set_read_timeout(None).ok();
            let mut eb = event_bus.write().unwrap();
            let cloned = stream.try_clone()?;
            eb.push(EventSink {
                stream: cloned,
                uid: peer_uid,
            });
            let ok = Response::ok_empty();
            send_response(&mut stream, &ok)?;
            // Keep connection alive — events will be pushed by broadcast_event()
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }

        let resp = dispatch(
            req,
            peer_uid,
            _peer_pid,
            &sessions,
            &users,
            &seats,
            &inhibitors,
            &power,
            &config,
            &event_bus,
        );
        send_response(&mut stream, &resp)?;
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch(
    req: Request,
    peer_uid: u32,
    _peer_pid: u32,
    sessions: &Sessions,
    users: &Users,
    seats: &Seats,
    inhibitors: &Inhibitors,
    power: &Power,
    config: &LogindConfig,
    event_bus: &EventBus,
) -> Response {
    match req {
        // ── Sessions ──────────────────────────────────────────────────────────
        Request::OpenSession {
            uid,
            username,
            leader_pid,
            session_type,
            session_class,
            tty,
            display,
            remote_host,
            remote_user,
            service,
            vt,
        } => {
            if peer_uid != 0 {
                return Response::err("only root can open sessions");
            }
            let sid = match sessions.lock().unwrap().open(
                uid,
                username.clone(),
                leader_pid,
                session_type,
                session_class,
                tty.clone(),
                display,
                remote_host.clone(),
                remote_user,
                service,
                vt,
            ) {
                Ok(id) => id,
                Err(e) => return Response::err(e.to_string()),
            };

            if let Err(e) = users
                .lock()
                .unwrap()
                .login(uid, username.clone(), sid, config)
            {
                return Response::err(e.to_string());
            }

            seats.lock().unwrap().add_session("seat0", sid);
            sessions.lock().unwrap().assign_seat(sid, "seat0".into());

            // utmp login record
            if let Some(ref tty) = tty {
                utmp::write_login(
                    leader_pid,
                    tty,
                    &username,
                    remote_host.as_deref().unwrap_or(""),
                    sid,
                );
            }

            // Inject session env for Flatpak/portals
            let runtime_dir = format!("/run/user/{}", uid);
            dbus_bridge::inject_session_env(uid, &runtime_dir, None);

            // Broadcast event
            broadcast_event(
                event_bus,
                &LogindEvent::SessionNew {
                    session_id: sid,
                    uid,
                    username: username.clone(),
                },
            );
            broadcast_event(event_bus, &LogindEvent::UserNew { uid, username });

            Response::ok(serde_json::json!({
                "session_id": sid,
                "runtime_dir": format!("/run/user/{}", uid),
                "seat": "seat0",
            }))
        }

        Request::CloseSession { session_id } => {
            let uid = sessions.lock().unwrap().uid_of(session_id);
            let seat = sessions.lock().unwrap().seat_of(session_id);

            let Some(uid) = uid else {
                return Response::err(format!("session {} not found", session_id));
            };

            if peer_uid != 0 && peer_uid != uid {
                return Response::err("permission denied");
            }

            // utmp logout
            let tty = sessions
                .lock()
                .unwrap()
                .get(session_id)
                .and_then(|s| s.tty.clone());
            if let Some(ref tty) = tty {
                let pid = sessions
                    .lock()
                    .unwrap()
                    .get(session_id)
                    .map(|s| s.leader_pid)
                    .unwrap_or(0);
                utmp::write_logout(pid, tty);
            }

            if let Some(ref s) = seat {
                seats.lock().unwrap().remove_session(s, session_id);
            }

            if let Err(e) = sessions.lock().unwrap().close(session_id) {
                return Response::err(e.to_string());
            }

            if let Err(e) = users.lock().unwrap().logout(uid, session_id, config) {
                log::warn!("logout cleanup uid={}: {}", uid, e);
            }

            broadcast_event(event_bus, &LogindEvent::SessionRemoved { session_id, uid });

            Response::ok_empty()
        }

        Request::ActivateSession { session_id } => {
            if let Err(e) = sessions.lock().unwrap().activate(session_id) {
                return Response::err(e.to_string());
            }
            let seat = sessions.lock().unwrap().seat_of(session_id);
            if let Some(s) = seat {
                seats.lock().unwrap().activate(&s, session_id).ok();
            }
            // VT switch if session has a VT
            let vt = sessions.lock().unwrap().vt_of(session_id);
            if let Some(n) = vt {
                seats.lock().unwrap().switch_to_vt(n).ok();
                broadcast_event(event_bus, &LogindEvent::VtSwitched { vt_number: n });
            }
            Response::ok_empty()
        }

        Request::LockSession { session_id } => {
            if let Err(e) = sessions.lock().unwrap().lock(session_id) {
                return Response::err(e.to_string());
            }
            broadcast_event(event_bus, &LogindEvent::SessionLocked { session_id });
            Response::ok_empty()
        }

        Request::UnlockSession { session_id } => {
            if let Err(e) = sessions.lock().unwrap().unlock(session_id) {
                return Response::err(e.to_string());
            }
            broadcast_event(event_bus, &LogindEvent::SessionUnlocked { session_id });
            Response::ok_empty()
        }

        Request::LockSessions => {
            sessions.lock().unwrap().lock_all();
            Response::ok_empty()
        }

        Request::UnlockSessions => {
            sessions.lock().unwrap().unlock_all();
            Response::ok_empty()
        }

        Request::ListSessions => {
            let sm = sessions.lock().unwrap();
            Response::ok(sm.all())
        }

        Request::GetSession { session_id } => match sessions.lock().unwrap().get(session_id) {
            Some(s) => Response::ok(s),
            None => Response::err(format!("session {} not found", session_id)),
        },

        Request::GetSessionByPid { pid } => match sessions.lock().unwrap().session_by_pid(pid) {
            Some(s) => Response::ok(s),
            None => Response::err(format!("no session for pid {}", pid)),
        },

        Request::SetIdleHint { session_id, idle } => {
            match sessions.lock().unwrap().set_idle_hint(session_id, idle) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::SetLockedHint { session_id, locked } => {
            match sessions.lock().unwrap().set_locked_hint(session_id, locked) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        // ── Users ─────────────────────────────────────────────────────────────
        Request::GetUser { uid } => {
            if peer_uid != 0 && peer_uid != uid {
                return Response::err("permission denied");
            }
            match users.lock().unwrap().get(uid) {
                Some(u) => Response::ok(u),
                None => Response::err(format!("uid={} not logged in", uid)),
            }
        }

        Request::ListUsers => {
            if peer_uid != 0 {
                return Response::err("only root can list users");
            }
            Response::ok(users.lock().unwrap().all())
        }

        Request::SetLinger { uid, enable } => {
            if peer_uid != 0 && peer_uid != uid {
                return Response::err("permission denied");
            }
            match users.lock().unwrap().set_linger(uid, enable) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::TerminateUser { uid } => {
            if peer_uid != 0 {
                return Response::err("only root can terminate users");
            }
            match users.lock().unwrap().terminate(uid) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        // ── Seats ─────────────────────────────────────────────────────────────
        Request::ListSeats => Response::ok(seats.lock().unwrap().all()),

        Request::GetSeat { seat_id } => match seats.lock().unwrap().get(&seat_id) {
            Some(s) => Response::ok(s),
            None => Response::err(format!("seat {} not found", seat_id)),
        },

        Request::ActivateSessionOnSeat {
            session_id,
            seat_id,
        } => {
            if let Err(e) = seats.lock().unwrap().activate(&seat_id, session_id) {
                return Response::err(e.to_string());
            }
            sessions.lock().unwrap().activate(session_id).ok();
            Response::ok_empty()
        }

        Request::SwitchTo { vt_number } => {
            if peer_uid != 0 {
                return Response::err("only root can switch VTs");
            }
            match seats.lock().unwrap().switch_to_vt(vt_number) {
                Ok(()) => {
                    broadcast_event(event_bus, &LogindEvent::VtSwitched { vt_number });
                    Response::ok_empty()
                }
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::TakeDevice { seat_id, devpath } => {
            if peer_uid != 0 {
                return Response::err("only root can take devices");
            }
            match seats.lock().unwrap().take_device(&seat_id, &devpath) {
                Ok(fd) => Response::ok(serde_json::json!({ "fd": fd, "paused": false })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::ReleaseDevice { seat_id, devpath } => {
            seats
                .lock()
                .unwrap()
                .release_device(&seat_id, &devpath)
                .ok();
            Response::ok_empty()
        }

        // ── Inhibitors ────────────────────────────────────────────────────────
        Request::TakeInhibitor {
            what,
            who,
            why,
            mode,
            uid,
            pid,
        } => {
            let id = inhibitors
                .lock()
                .unwrap()
                .take(what, who, why, mode, uid, pid);
            Response::ok(serde_json::json!({ "inhibitor_id": id }))
        }

        Request::ReleaseInhibitor { inhibitor_id } => {
            if inhibitors.lock().unwrap().release(inhibitor_id) {
                Response::ok_empty()
            } else {
                Response::err(format!("inhibitor {} not found", inhibitor_id))
            }
        }

        Request::ListInhibitors => Response::ok(inhibitors.lock().unwrap().all()),

        // ── Power ─────────────────────────────────────────────────────────────
        Request::PowerOff { interactive } => {
            if peer_uid != 0 {
                return Response::err("only root can power off");
            }
            let inh = inhibitors.lock().unwrap();
            match power.lock().unwrap().power_off(&inh, interactive) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::Reboot { interactive } => {
            if peer_uid != 0 {
                return Response::err("only root can reboot");
            }
            let inh = inhibitors.lock().unwrap();
            match power.lock().unwrap().reboot(&inh, interactive) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::RebootToFirmwareSetup { interactive } => {
            if peer_uid != 0 {
                return Response::err("only root");
            }
            let inh = inhibitors.lock().unwrap();
            match power.lock().unwrap().reboot_to_firmware(&inh, interactive) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::Halt { interactive } => {
            if peer_uid != 0 {
                return Response::err("only root can halt");
            }
            let inh = inhibitors.lock().unwrap();
            match power.lock().unwrap().halt(&inh, interactive) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::Suspend { interactive } => {
            let inh = inhibitors.lock().unwrap();
            match power.lock().unwrap().suspend(&inh, interactive) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::Hibernate { interactive } => {
            let inh = inhibitors.lock().unwrap();
            match power.lock().unwrap().hibernate(&inh, interactive) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::HybridSleep { interactive } => {
            let inh = inhibitors.lock().unwrap();
            match power.lock().unwrap().hybrid_sleep(&inh, interactive) {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::SuspendThenHibernate { interactive } => {
            let inh = inhibitors.lock().unwrap();
            match power
                .lock()
                .unwrap()
                .suspend_then_hibernate(&inh, interactive)
            {
                Ok(()) => Response::ok_empty(),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::CanPowerOff => Response::ok(power.lock().unwrap().can_power_off()),
        Request::CanReboot => Response::ok(power.lock().unwrap().can_reboot()),
        Request::CanSuspend => Response::ok(power.lock().unwrap().can_suspend_q()),
        Request::CanHibernate => Response::ok(power.lock().unwrap().can_hibernate_q()),
        Request::CanHybridSleep => Response::ok(power.lock().unwrap().can_hybrid_sleep_q()),
        Request::CanSuspendThenHibernate => {
            Response::ok(power.lock().unwrap().can_suspend_then_hibernate_q())
        }

        // ── Brightness ────────────────────────────────────────────────────────
        Request::SetBrightness {
            subsystem,
            name,
            value,
        } => {
            match power
                .lock()
                .unwrap()
                .set_brightness(&subsystem, &name, value)
            {
                Ok(()) => {
                    broadcast_event(
                        event_bus,
                        &LogindEvent::BrightnessChanged {
                            name: name.clone(),
                            value,
                        },
                    );
                    Response::ok_empty()
                }
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::GetBrightness { subsystem, name } => {
            match power.lock().unwrap().get_brightness(&subsystem, &name) {
                Ok(v) => Response::ok(serde_json::json!({ "value": v })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        // ── Scheduled shutdown ────────────────────────────────────────────────
        Request::ScheduleShutdown { action, usec } => {
            if peer_uid != 0 {
                return Response::err("only root");
            }
            match power
                .lock()
                .unwrap()
                .schedule_shutdown(action.clone(), usec)
            {
                Ok(()) => {
                    broadcast_event(
                        event_bus,
                        &LogindEvent::ShutdownScheduled {
                            action,
                            time_usec: usec,
                        },
                    );
                    Response::ok_empty()
                }
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::CancelScheduledShutdown => {
            power.lock().unwrap().cancel_scheduled_shutdown();
            Response::ok_empty()
        }

        // ── Subscribe ─────────────────────────────────────────────────────────
        Request::Subscribe => Response::ok_empty(), // Handled above in handle()

        // ── Status / Version ──────────────────────────────────────────────────
        Request::Status => {
            let sm = sessions.lock().unwrap();
            let um = users.lock().unwrap();
            let st = seats.lock().unwrap();
            let ih = inhibitors.lock().unwrap();
            Response::ok(serde_json::json!({
                "version":    env!("CARGO_PKG_VERSION"),
                "sessions":   sm.all().len(),
                "users":      um.all().len(),
                "seats":      st.list(),
                "inhibitors": ih.all().len(),
                "can_suspend": power.lock().unwrap().can_suspend,
                "can_hibernate": power.lock().unwrap().can_hibernate,
            }))
        }

        Request::Version => Response::ok(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": "quantra-logind/2.0",
            "compat": ["systemd-logind/261"],
        })),
    }
}

// ── Event broadcasting ────────────────────────────────────────────────────────

fn broadcast_event(event_bus: &EventBus, event: &LogindEvent) {
    let json = match serde_json::to_vec(event) {
        Ok(j) => j,
        Err(e) => {
            log::debug!("event serialize: {}", e);
            return;
        }
    };
    let len = (json.len() as u32).to_le_bytes();

    let mut bus = event_bus.write().unwrap();
    bus.retain_mut(|sink| {
        sink.stream.write_all(&len).is_ok() && sink.stream.write_all(&json).is_ok()
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn send_response(stream: &mut UnixStream, resp: &Response) -> Result<()> {
    let out = serde_json::to_vec(resp)?;
    let len = (out.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(&out)?;
    Ok(())
}

fn peer_cred(stream: &UnixStream) -> (u32, u32) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 {
        (ucred.uid, ucred.pid as u32)
    } else {
        (u32::MAX, 0)
    }
}
