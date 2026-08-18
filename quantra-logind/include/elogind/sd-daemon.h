/* elogind-compat alias. Same libqlogind.so symbols, exposed at the
 * include path GNOME/COSMIC's #include <elogind/sd-daemon.h> expects
 * (see gnome-shell's 0001-shell-elogind-support patch). */
#include <qlogind/sd-daemon.h>
