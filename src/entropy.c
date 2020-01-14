#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int get_system_entropy(void* buf, unsigned int length) {
    // TODO: ideally we should use getentropy from sys/random.h if it's
    // available.
    int file = open("/dev/urandom", O_RDONLY);
    int read_bytes = read(file, buf, length);
    close(file);
    if(read_bytes < length) return -1;
    else return 0;
}
