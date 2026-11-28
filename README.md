# To compile:

aarch64-linux-gnu-gcc -std=gnu11 -O3 -pthread \
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
    -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes \
    -Wmissing-declarations -Wold-style-definition -Wredundant-decls \
    -Wnested-externs -Wwrite-strings -Wundef -Wformat=2 -Wformat-security \
    -Wnull-dereference -Wdouble-promotion -Wfloat-equal -Wpointer-arith \
    -Wbad-function-cast -Wstrict-aliasing=2 -Wswitch-enum -Wswitch-default \
    -Wunused -Wunused-macros -Wunused-result -Wvla \
    -Wstack-usage=65536 -Wframe-larger-than=65536 \
    -fanalyzer \
    -static \
    -o cproxy_aarch64 src/cproxy.c
