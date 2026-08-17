//! Seat Manager — VT switching, device tracking, DRM/evdev fd passing
//!
//! # Seat concept
//!
//! A seat is a collection of hardware that allows one user to interact with
//! the system simultaneously. Most systems have one seat (`seat0`) consisting
//! of:
//! - One or more display outputs (DRM devices: /dev/dri/card*)
//! - Keyboard/mouse/touchscreen (evdev devices: /dev/input/event*)
//! - Sound card (ALSA devices: /dev/snd/*)
//!
//! # VT switching
//!
//! Virtual terminal switching uses the `VT_ACTIVATE` ioctl on `/dev/tty0`.
//! `SwitchTo { vt_number }` activates the specified VT.
//!
//! COSMIC desktop, SDDM, and GDM use this to switch between the greeter
//! and user sessions.
//!
//! # TakeDevice / ReleaseDevice
//!
//! Compositors (COSMIC, wlroots, etc.) call `TakeDevice` to get an
//! open file descriptor to DRM/evdev devices WITHOUT needing to be root.
//! quantra-logind opens the device and passes the fd via SCM_RIGHTS.
//!
//! This is the seat device access protocol used by libseat and wlroots.

use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::os::unix::io::RawFd;
use std::path::Path;

pub struct SeatManager {
    seats: HashMap<String, Seat>,
}

impl SeatManager {
    pub fn new() -> Self {
        Self {
            seats: HashMap::new(),
        }
    }

    /// Detect seat0 from /sys/class/drm and /sys/class/input
    pub fn detect(&mut self) -> Result<()> {
        let mut seat0 = Seat::new("seat0");

        // DRM devices → can_graphical
        if let Ok(entries) = fs::read_dir("/sys/class/drm") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("card") && !name.contains('-') {
                    let dev = format!("/dev/dri/{}", name);
                    if Path::new(&dev).exists() {
                        seat0.devices.push(SeatDevice {
                            path: dev,
                            kind: DeviceKind::Drm,
                            fd: None,
                            paused: false,
                        });
                        seat0.can_graphical = true;
                    }
                }
            }
        }

        // Input devices → evdev
        if let Ok(entries) = fs::read_dir("/sys/class/input") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("event") {
                    let dev = format!("/dev/input/{}", name);
                    if Path::new(&dev).exists() {
                        seat0.devices.push(SeatDevice {
                            path: dev,
                            kind: DeviceKind::Evdev,
                            fd: None,
                            paused: false,
                        });
                    }
                }
            }
        }

        // Sound devices
        if let Ok(entries) = fs::read_dir("/dev/snd") {
            for e in entries.flatten() {
                let dev = e.path().to_string_lossy().into_owned();
                seat0.devices.push(SeatDevice {
                    path: dev,
                    kind: DeviceKind::Sound,
                    fd: None,
                    paused: false,
                });
            }
        }

        log::info!(
            "seat0: {} DRM, {} evdev, {} sound devices",
            seat0
                .devices
                .iter()
                .filter(|d| d.kind == DeviceKind::Drm)
                .count(),
            seat0
                .devices
                .iter()
                .filter(|d| d.kind == DeviceKind::Evdev)
                .count(),
            seat0
                .devices
                .iter()
                .filter(|d| d.kind == DeviceKind::Sound)
                .count(),
        );

        seat0.can_tty = Path::new("/dev/tty0").exists();
        self.seats.insert("seat0".to_string(), seat0);
        Ok(())
    }

    pub fn add_session(&mut self, seat_id: &str, sid: SessionId) {
        if let Some(seat) = self.seats.get_mut(seat_id) {
            if !seat.sessions.contains(&sid) {
                seat.sessions.push(sid);
            }
            if seat.active_session.is_none() {
                seat.active_session = Some(sid);
                log::info!("seat {}: session {} active (first)", seat_id, sid);
            }
        }
    }

    pub fn remove_session(&mut self, seat_id: &str, sid: SessionId) {
        if let Some(seat) = self.seats.get_mut(seat_id) {
            seat.sessions.retain(|&s| s != sid);
            if seat.active_session == Some(sid) {
                seat.active_session = seat.sessions.first().copied();
                log::info!(
                    "seat {}: {} removed, active now: {:?}",
                    seat_id,
                    sid,
                    seat.active_session
                );
            }
        }
    }

    pub fn activate(&mut self, seat_id: &str, sid: SessionId) -> Result<()> {
        let seat = self
            .seats
            .get_mut(seat_id)
            .ok_or_else(|| anyhow::anyhow!("seat {} not found", seat_id))?;
        if !seat.sessions.contains(&sid) {
            return Err(anyhow::anyhow!("session {} not on seat {}", sid, seat_id));
        }
        seat.active_session = Some(sid);
        Ok(())
    }

    /// Switch to virtual terminal N.
    ///
    /// Uses VT_ACTIVATE ioctl on /dev/tty0.
    /// COSMIC greeter, SDDM, wlroots all call this.
    pub fn switch_to_vt(&self, vt: u32) -> Result<()> {
        if vt == 0 || vt > 63 {
            return Err(anyhow::anyhow!("invalid VT number: {}", vt));
        }

        const VT_ACTIVATE: libc::c_ulong = 0x5606;
        const VT_WAITACTIVE: libc::c_ulong = 0x5607;

        let tty_path = std::ffi::CString::new("/dev/tty0").unwrap();
        let fd = unsafe {
            libc::open(
                tty_path.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "/dev/tty0: {}",
                std::io::Error::last_os_error()
            ));
        }

        let ret = unsafe { libc::ioctl(fd, VT_ACTIVATE, vt as libc::c_long) };
        if ret != 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "VT_ACTIVATE {}: {}",
                vt,
                std::io::Error::last_os_error()
            ));
        }

        // Wait for VT switch to complete
        unsafe {
            libc::ioctl(fd, VT_WAITACTIVE, vt as libc::c_long);
            libc::close(fd);
        }

        log::info!("VT switched to tty{}", vt);
        Ok(())
    }

    /// Open a device and return the fd for passing to compositor via SCM_RIGHTS.
    ///
    /// The compositor (COSMIC, wlroots, Mutter) calls TakeDevice to get an
    /// fd to /dev/dri/cardN or /dev/input/eventN without needing root.
    pub fn take_device(&mut self, seat_id: &str, devpath: &str) -> Result<RawFd> {
        let seat = self
            .seats
            .get_mut(seat_id)
            .ok_or_else(|| anyhow::anyhow!("seat {} not found", seat_id))?;

        // Verify device belongs to this seat
        let dev_entry = seat
            .devices
            .iter_mut()
            .find(|d| d.path == devpath)
            .ok_or_else(|| anyhow::anyhow!("device {} not on seat {}", devpath, seat_id))?;

        if let Some(fd) = dev_entry.fd {
            // Already open — return existing fd
            return Ok(fd);
        }

        // Open device
        let flags = match dev_entry.kind {
            DeviceKind::Drm => libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY,
            DeviceKind::Evdev => libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY,
            _ => libc::O_RDONLY | libc::O_CLOEXEC,
        };

        let path_cstr = std::ffi::CString::new(devpath)
            .map_err(|_| anyhow::anyhow!("invalid devpath: {}", devpath))?;

        let fd = unsafe { libc::open(path_cstr.as_ptr(), flags) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "open {}: {}",
                devpath,
                std::io::Error::last_os_error()
            ));
        }

        dev_entry.fd = Some(fd);
        log::info!("TakeDevice: {} fd={}", devpath, fd);
        Ok(fd)
    }

    /// Release a device fd previously taken by TakeDevice.
    pub fn release_device(&mut self, seat_id: &str, devpath: &str) -> Result<()> {
        let seat = self
            .seats
            .get_mut(seat_id)
            .ok_or_else(|| anyhow::anyhow!("seat {} not found", seat_id))?;

        if let Some(dev) = seat.devices.iter_mut().find(|d| d.path == devpath)
            && let Some(fd) = dev.fd.take()
        {
            unsafe { libc::close(fd) };
            log::info!("ReleaseDevice: {} fd closed", devpath);
        }
        Ok(())
    }

    /// Pause a device (called during VT switch away from session).
    #[allow(dead_code)]
    pub fn pause_device(&mut self, seat_id: &str, devpath: &str) {
        if let Some(seat) = self.seats.get_mut(seat_id)
            && let Some(dev) = seat.devices.iter_mut().find(|d| d.path == devpath)
        {
            dev.paused = true;
            // For DRM: set master to nobody so session loses modesetting control
            if dev.kind == DeviceKind::Drm
                && let Some(fd) = dev.fd
            {
                const DRM_IOCTL_DROP_MASTER: libc::c_ulong = 0x64;
                unsafe { libc::ioctl(fd, DRM_IOCTL_DROP_MASTER, 0) };
            }
        }
    }

    /// Resume a device (called when VT switches back to session).
    #[allow(dead_code)]
    pub fn resume_device(&mut self, seat_id: &str, devpath: &str) {
        if let Some(seat) = self.seats.get_mut(seat_id)
            && let Some(dev) = seat.devices.iter_mut().find(|d| d.path == devpath)
        {
            dev.paused = false;
            if dev.kind == DeviceKind::Drm
                && let Some(fd) = dev.fd
            {
                const DRM_IOCTL_SET_MASTER: libc::c_ulong = 0x1e;
                unsafe { libc::ioctl(fd, DRM_IOCTL_SET_MASTER, 0) };
            }
        }
    }

    /// Get current VT number from kernel.
    #[allow(dead_code)]
    pub fn current_vt(&self) -> Option<u32> {
        const VT_GETSTATE: libc::c_ulong = 0x5603;
        #[repr(C)]
        struct VtStat {
            v_active: u16,
            v_signal: u16,
            v_state: u16,
        }

        let tty_cstr = std::ffi::CString::new("/dev/tty0").unwrap();
        let fd = unsafe {
            libc::open(
                tty_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY,
            )
        };
        if fd < 0 {
            return None;
        }

        let mut state: VtStat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::ioctl(fd, VT_GETSTATE, &mut state as *mut VtStat) };
        unsafe { libc::close(fd) };
        if ret == 0 {
            Some(state.v_active as u32)
        } else {
            None
        }
    }

    pub fn get(&self, id: &str) -> Option<&Seat> {
        self.seats.get(id)
    }
    pub fn all(&self) -> Vec<&Seat> {
        self.seats.values().collect()
    }
    pub fn list(&self) -> Vec<&str> {
        self.seats.keys().map(|s| s.as_str()).collect()
    }
}
