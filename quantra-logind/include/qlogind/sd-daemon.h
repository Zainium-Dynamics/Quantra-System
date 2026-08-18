/* qlogind sd-daemon.h subset. Same function signatures as systemd's
 * sd-daemon.h, backed by libqlogind.so instead of libsystemd.
 * See src/ffi/daemon.rs for the implementation.
 */
#ifndef QLOGIND_SD_DAEMON_H
#define QLOGIND_SD_DAEMON_H

#ifdef __cplusplus
extern "C" {
#endif

int sd_booted(void);
int sd_notify(int unset_environment, const char *state);

/* sd_notifyf is not implemented (see daemon.rs). Not declared here so
 * a caller referencing it fails at compile time, not link time. */

#ifdef __cplusplus
}
#endif

#endif /* QLOGIND_SD_DAEMON_H */
