#include <errno.h>
#include <fcntl.h>
#include <libseat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void enabled(struct libseat *seat, void *data) {
    (void)seat;
    (*(int *)data)++;
}
static void disabled(struct libseat *seat, void *data) {
    (void)data;
    libseat_disable_seat(seat);
}
static int run(void) {
    int count = 0;
    const struct libseat_seat_listener listener = {
        .enable_seat = enabled,
        .disable_seat = disabled,
    };
    struct libseat *seat = libseat_open_seat(&listener, &count);
    if (!seat || getenv("SEATD_FD")) return 10;
    while (!count) if (libseat_dispatch(seat, 2000) < 0) return 11;
    const char *expected = getenv("CONTEXT_TEST_SEAT");
    if (!expected || count != 1 || strcmp(libseat_seat_name(seat), expected)) return 12;
    int first_fd = -1, second_fd = -1;
    int first = libseat_open_device(seat, "/dev/null", &first_fd);
    int second = libseat_open_device(seat, "/dev/null", &second_fd);
    if (first < 0 || first != second || first_fd < 0 || second_fd < 0 || first_fd == second_fd) {
        fprintf(stderr, "device opens: slots %d/%d descriptors %d/%d errno %d (%s)\n", first, second, first_fd, second_fd, errno, strerror(errno));
        return 14;
    }
    if (!(fcntl(first_fd, F_GETFD) & FD_CLOEXEC) || !(fcntl(second_fd, F_GETFD) & FD_CLOEXEC)) return 15;
    if (libseat_close_device(seat, first) < 0) return 16;
    close(first_fd);
    if (libseat_close_device(seat, second) < 0) return 17;
    close(second_fd);
    if (libseat_close_seat(seat) < 0) return 13;
    return 0;
}
int main(void) {
    if (geteuid() == 0 || getenv("MULTISEATD_AUTHORITY_FD")) return 1;
    const char *authority = getenv("CONTEXT_TEST_AUTHORITY_FD");
    if (!authority) return 2;
    errno = 0;
    if (fcntl(atoi(authority), F_GETFD) != -1 || errno != EBADF) return 3;
    const char *endpoint = getenv("SEATD_FD");
    if (!endpoint) return 4;
    const char *sentinel = getenv("CONTEXT_TEST_SENTINEL_FD");
    if (sentinel && fcntl(atoi(sentinel), F_GETFD) != -1) return 6;
    if (getenv("CONTEXT_TEST_METADATA")) {
        const char *seat = getenv("XDG_SEAT");
        const char *expected = getenv("CONTEXT_TEST_SEAT");
        if (!seat || !expected || strcmp(seat, expected) || getenv("XDG_VTNR")) return 7;
    }
    int retained = dup(atoi(endpoint));
    if (retained < 0) return 4;
    int result = run();
    if (result) return result;
    char value[32];
    snprintf(value, sizeof value, "%d", retained);
    if (setenv("SEATD_FD", value, 1)) return 5;
    return run();
}
