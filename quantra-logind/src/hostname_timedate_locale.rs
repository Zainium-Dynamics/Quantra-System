//! org.freedesktop.hostname1 / timedate1 / locale1 — the three small
//! D-Bus services real systemd ships as separate daemons (hostnamed,
//! timedated, localed). quantra-logind only did org.freedesktop.login1
//! before this file; COSMIC's hostname page (cosmic-settings) and
//! RTC/timezone sync (cosmic-settings-daemon) need these three too.
//!
//! Deliberately minimal: plain file-backed state under
//! /overlayer/syshub/etc/, no polkit authorization check on the
//! "interactive" calls yet (every *_interactive method just accepts —
//! same trust level a local root-owned bus name already implies, but
//! real systemd gates these behind polkit; add that once quantra's own
//! polkit integration exists). NTP is state-only — there's no time-sync
//! daemon wired up here to actually start/stop.

use oxibus_client::{BoxFuture, Interface, MethodError, MethodResult};
use oxibus_core::{ArrayValue, Type, Value};
use std::fs;
use std::path::Path;

const ETC: &str = "/overlayer/syshub/etc";

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn write_etc(name: &str, contents: &str) -> std::io::Result<()> {
    if !Path::new(ETC).exists() {
        fs::create_dir_all(ETC)?;
    }
    fs::write(format!("{ETC}/{name}"), contents)
}

// ─────────────────────────────── hostname1 ──────────────────────────────

pub struct Hostname1;

impl Interface for Hostname1 {
    fn name(&self) -> &str {
        "org.freedesktop.hostname1"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.hostname1">
            <method name="SetHostname">
                <arg type="s" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <method name="SetStaticHostname">
                <arg type="s" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <method name="SetPrettyHostname">
                <arg type="s" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <property name="Hostname" type="s" access="read"/>
            <property name="StaticHostname" type="s" access="read"/>
            <property name="PrettyHostname" type="s" access="read"/>
            <property name="IconName" type="s" access="read"/>
            <property name="Chassis" type="s" access="read"/>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "SetHostname" | "SetStaticHostname" => {
                    let name = args
                        .first()
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| MethodError::invalid_args("expected hostname string"))?;
                    write_etc("hostname", &format!("{name}\n")).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    // best-effort live sethostname(2); non-fatal if it fails (e.g. no CAP_SYS_ADMIN)
                    unsafe {
                        libc::sethostname(name.as_ptr() as *const i8, name.len());
                    }
                    Ok(Vec::new())
                }
                "SetPrettyHostname" => {
                    let name = args
                        .first()
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| MethodError::invalid_args("expected hostname string"))?;
                    write_etc("machine-info", &format!("PRETTY_HOSTNAME=\"{name}\"\n")).map_err(
                        |e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()),
                    )?;
                    Ok(Vec::new())
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }

    fn get_property(&self, name: &str) -> Option<Value> {
        match name {
            "Hostname" | "StaticHostname" => Some(Value::string(
                read_trim(&format!("{ETC}/hostname")).unwrap_or_else(|| "localhost".to_string()),
            )),
            "PrettyHostname" => {
                let content = fs::read_to_string(format!("{ETC}/machine-info")).ok()?;
                let pretty = content
                    .lines()
                    .find_map(|l| l.strip_prefix("PRETTY_HOSTNAME="))
                    .map(|s| s.trim_matches('"').to_string())
                    .unwrap_or_default();
                Some(Value::string(pretty))
            }
            "IconName" => Some(Value::string("computer".to_string())),
            "Chassis" => Some(Value::string("desktop".to_string())),
            _ => None,
        }
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        ["Hostname", "StaticHostname", "PrettyHostname", "IconName", "Chassis"]
            .iter()
            .filter_map(|k| self.get_property(k).map(|v| (k.to_string(), v)))
            .collect()
    }
}

// ─────────────────────────────── timedate1 ──────────────────────────────

pub struct Timedate1;

impl Interface for Timedate1 {
    fn name(&self) -> &str {
        "org.freedesktop.timedate1"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.timedate1">
            <method name="SetTimezone">
                <arg type="s" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <method name="SetLocalRTC">
                <arg type="b" direction="in"/>
                <arg type="b" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <method name="SetNTP">
                <arg type="b" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <property name="Timezone" type="s" access="read"/>
            <property name="LocalRTC" type="b" access="read"/>
            <property name="NTP" type="b" access="read"/>
            <property name="NTPSynchronized" type="b" access="read"/>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "SetTimezone" => {
                    let tz = args
                        .first()
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| MethodError::invalid_args("expected timezone string"))?;
                    let zoneinfo = format!("/overlayer/syshub/share/zoneinfo/{tz}");
                    if !Path::new(&zoneinfo).exists() {
                        return Err(MethodError::invalid_args(format!(
                            "unknown timezone \"{tz}\""
                        )));
                    }
                    let localtime = format!("{ETC}/localtime");
                    let _ = fs::remove_file(&localtime);
                    std::os::unix::fs::symlink(&zoneinfo, &localtime).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    write_etc("timezone", &format!("{tz}\n")).ok();
                    Ok(Vec::new())
                }
                "SetLocalRTC" => {
                    let local = matches!(args.first(), Some(Value::Boolean(true)));
                    write_etc("adjtime", if local { "0.0 0 0\n0\nLOCAL\n" } else { "0.0 0 0\n0\nUTC\n" })
                        .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    Ok(Vec::new())
                }
                "SetNTP" => {
                    let enabled = matches!(args.first(), Some(Value::Boolean(true)));
                    // state-only -- no time-sync daemon started/stopped here yet
                    write_etc("ntp-enabled", if enabled { "1\n" } else { "0\n" }).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    Ok(Vec::new())
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }

    fn get_property(&self, name: &str) -> Option<Value> {
        match name {
            "Timezone" => {
                let link = fs::read_link(format!("{ETC}/localtime")).ok()?;
                let s = link.to_string_lossy();
                let tz = s.rsplit("zoneinfo/").next().unwrap_or("UTC");
                Some(Value::string(tz.to_string()))
            }
            "LocalRTC" => {
                let adjtime = fs::read_to_string(format!("{ETC}/adjtime")).unwrap_or_default();
                Some(Value::Boolean(adjtime.lines().last().map(|l| l.trim()) == Some("LOCAL")))
            }
            "NTP" => Some(Value::Boolean(
                read_trim(&format!("{ETC}/ntp-enabled")).as_deref() == Some("1"),
            )),
            "NTPSynchronized" => Some(Value::Boolean(false)),
            _ => None,
        }
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        ["Timezone", "LocalRTC", "NTP", "NTPSynchronized"]
            .iter()
            .filter_map(|k| self.get_property(k).map(|v| (k.to_string(), v)))
            .collect()
    }
}

// ──────────────────────────────── locale1 ────────────────────────────────

pub struct Locale1;

impl Interface for Locale1 {
    fn name(&self) -> &str {
        "org.freedesktop.locale1"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.locale1">
            <method name="SetLocale">
                <arg type="as" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <method name="SetVConsoleKeyboard">
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="b" direction="in"/>
                <arg type="b" direction="in"/>
            </method>
            <property name="Locale" type="as" access="read"/>
            <property name="VConsoleKeymap" type="s" access="read"/>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "SetLocale" => {
                    let locales: Vec<String> = match args.first() {
                        Some(Value::Array(arr)) => {
                            arr.elements.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
                        }
                        _ => return Err(MethodError::invalid_args("expected array of strings")),
                    };
                    let content = locales.iter().map(|s| format!("{s}\n")).collect::<String>();
                    write_etc("locale.conf", &content).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    Ok(Vec::new())
                }
                "SetVConsoleKeyboard" => {
                    let keymap = args
                        .first()
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| MethodError::invalid_args("expected keymap string"))?;
                    write_etc("vconsole.conf", &format!("KEYMAP={keymap}\n")).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    Ok(Vec::new())
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }

    fn get_property(&self, name: &str) -> Option<Value> {
        match name {
            "Locale" => {
                let content = fs::read_to_string(format!("{ETC}/locale.conf")).unwrap_or_default();
                let entries: Vec<Value> = content
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| Value::string(l.trim().to_string()))
                    .collect();
                let entries = if entries.is_empty() {
                    vec![Value::string("LANG=C.UTF-8".to_string())]
                } else {
                    entries
                };
                Some(Value::Array(ArrayValue::new(Type::String, entries)))
            }
            "VConsoleKeymap" => {
                let content = fs::read_to_string(format!("{ETC}/vconsole.conf")).unwrap_or_default();
                let km = content
                    .lines()
                    .find_map(|l| l.strip_prefix("KEYMAP="))
                    .unwrap_or("us")
                    .to_string();
                Some(Value::string(km))
            }
            _ => None,
        }
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        ["Locale", "VConsoleKeymap"]
            .iter()
            .filter_map(|k| self.get_property(k).map(|v| (k.to_string(), v)))
            .collect()
    }
}
