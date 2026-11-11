#define _GNU_SOURCE
#include <libseat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void enable(struct libseat *seat, void *data) {(void)seat; *(int *)data=1;}
static void disable(struct libseat *seat, void *data) {(void)data; libseat_disable_seat(seat);}
int main(void) {
    const char *value=getenv("MULTISEATD_AUTHORITY_FD");
    if (geteuid()==0 || !value || getenv("SEATD_FD")) return 1;
    int authority=atoi(value); struct stat before;
    if (fstat(authority,&before)) return 2;
    int enabled=0; struct libseat_seat_listener listener={.enable_seat=enable,.disable_seat=disable};
    struct libseat *seat=libseat_open_seat(&listener,&enabled);
    if (!seat || getenv("MULTISEATD_AUTHORITY_FD") || getenv("SEATD_FD")) return 3;
    if (strcmp(libseat_seat_name(seat),getenv("XDG_SEAT"))) return 4;
    int endpoint=libseat_get_fd(seat);
    if (endpoint<3 || !(fcntl(endpoint,F_GETFD)&FD_CLOEXEC)) return 5;
    DIR *directory=opendir("/proc/self/fd"); if (!directory) return 6;
    struct dirent *entry;
    while ((entry=readdir(directory))) {
        if (entry->d_name[0]=='.') continue;
        int fd=atoi(entry->d_name); struct stat actual;
        if (fd>2 && fd!=dirfd(directory) && (fd!=endpoint || fstat(fd,&actual) || (actual.st_dev==before.st_dev && actual.st_ino==before.st_ino))) return 7;
    }
    closedir(directory);
    while (!enabled) if (libseat_dispatch(seat,2000)<0) return 8;
    int first_fd=-1,second_fd=-1;
    int first=libseat_open_device(seat,"/dev/null",&first_fd),second=libseat_open_device(seat,"/dev/null",&second_fd);
    if (first<0 || first!=second || first_fd<0 || second_fd<0 || first_fd==second_fd) return 9;
    if (!(fcntl(first_fd,F_GETFD)&FD_CLOEXEC) || !(fcntl(second_fd,F_GETFD)&FD_CLOEXEC)) return 10;
    if (libseat_close_device(seat,first)) return 11;
    close(first_fd);
    if (libseat_close_device(seat,second)) return 12;
    close(second_fd);
    return libseat_close_seat(seat)==0 ? 0 : 13;
}
