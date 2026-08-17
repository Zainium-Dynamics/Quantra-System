/* qlogind sd-login.h subset. Same function signatures as systemd's
 * sd-login.h, backed by libqlogind.so talking to quantra-logind's
 * control socket. See src/ffi/login.rs for the implementation and the
 * known GetUser/ListUsers ACL gap.
 */
#ifndef QLOGIND_SD_LOGIN_H
#define QLOGIND_SD_LOGIN_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int sd_pid_get_session(pid_t pid, char **session);
int sd_session_is_active(const char *session);
int sd_session_get_state(const char *session, char **state);
int sd_session_get_seat(const char *session, char **seat);
int sd_uid_get_state(uid_t uid, char **state);
int sd_seat_get_active(const char *seat, char **session, uid_t *uid);

#ifdef __cplusplus
}
#endif

#endif /* QLOGIND_SD_LOGIN_H */
