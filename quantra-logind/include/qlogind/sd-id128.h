/* qlogind sd-id128.h subset. Same layout as systemd's sd_id128_t, no
 * quantra-logind dependency. See src/ffi/id128.rs.
 */
#ifndef QLOGIND_SD_ID128_H
#define QLOGIND_SD_ID128_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union sd_id128 {
    uint8_t bytes[16];
    uint64_t qwords[2];
} sd_id128_t;

int sd_id128_get_machine(sd_id128_t *ret);
int sd_id128_get_boot(sd_id128_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* QLOGIND_SD_ID128_H */
