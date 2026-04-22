CC=gcc
CFLAGS=-Iinclude

SIMULATORS=sim_mem sim_fd sim_fork sim_cpu sim_socket sim_combo

.PHONY: all clean simulators

all: processguard simulators

processguard:
	$(CC) $(CFLAGS) src/*.c -o processguard

simulators: $(SIMULATORS)

sim_mem: simulators/sim_mem.c
	$(CC) simulators/sim_mem.c -o sim_mem

sim_fd: simulators/sim_fd.c
	$(CC) simulators/sim_fd.c -o sim_fd

sim_fork: simulators/sim_fork.c
	$(CC) simulators/sim_fork.c -o sim_fork

sim_cpu: simulators/sim_cpu.c
	$(CC) simulators/sim_cpu.c -o sim_cpu

sim_socket: simulators/sim_socket.c
	$(CC) simulators/sim_socket.c -o sim_socket

sim_combo: simulators/sim_combo.c
	$(CC) simulators/sim_combo.c -o sim_combo

clean:
	rm -f processguard $(SIMULATORS)
