// SPDX-FileCopyrightText: (c) 2021-2024 Shawn Silverman <shawn@pobox.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// qnethernet_hal.cpp implements the hardware abstraction layer (HAL).
// This file is part of the QNEthernet library.

// C includes
#include <unistd.h>

#include "qnethernet_opts.h"

// C++ includes
#if QNETHERNET_CUSTOM_WRITE
#include <cerrno>
#endif  // QNETHERNET_CUSTOM_WRITE
#include <cstdint>
#include <cstdlib>

#include <Print.h>

#include "lwip/arch.h"
#include "security/RandomDevice.h"

extern "C" {
u32_t sys_now(void);
}  // extern "C"

// --------------------------------------------------------------------------
//  stdio
// --------------------------------------------------------------------------

#if QNETHERNET_CUSTOM_WRITE

// The user program can set these to something initialized. For example,
// `&Serial`, after `Serial.begin(speed)`.
namespace qindesign {
namespace network {

Print *volatile stdoutPrint = nullptr;
Print *volatile stderrPrint = nullptr;

}  // namespace network
}  // namespace qindesign

#else

#include <Arduino.h>  // For Serial

#endif  // QNETHERNET_CUSTOM_WRITE

extern "C" {

// Gets the Print* for the given file descriptor.
static inline Print *getPrint(int file) {
  switch (file) {
#if QNETHERNET_CUSTOM_WRITE
    case STDOUT_FILENO:
      return ::qindesign::network::stdoutPrint;
    case STDERR_FILENO:
      return ::qindesign::network::stderrPrint;
#else
    case STDOUT_FILENO:
    case STDERR_FILENO:
      return &Serial;
#endif  // QNETHERNET_CUSTOM_WRITE
    case STDIN_FILENO:
      return nullptr;
    default:
      return reinterpret_cast<Print *>(file);
  }
}

#if QNETHERNET_CUSTOM_WRITE

// Define this function to provide expanded stdio output behaviour. This should
// work for Newlib-based systems.
// See: https://forum.pjrc.com/threads/28473-Quick-Guide-Using-printf()-on-Teensy-ARM
// Note: Can't define as weak by default because we don't know which `_write`
//       would be chosen by the linker, this one or the one defined elsewhere
//       (Print.cpp, for example)
int _write(int file, const void *buf, size_t len) {
  Print *out = getPrint(file);
  if (out == nullptr) {
    errno = EBADF;
    return -1;
  }

  return out->write(static_cast<const uint8_t *>(buf), len);
}

#endif  // QNETHERNET_CUSTOM_WRITE

// Ensures the Print object is flushed because fflush() just flushes by writing
// to the FILE*. This doesn't necessarily send all the bytes right away. For
// example, Serial/USB output behaves this way.
void qnethernet_stdio_flush(int file) {
  Print *p = getPrint(file);
  if (p != nullptr) {
    p->flush();
  }
}

}  // extern "C"

// --------------------------------------------------------------------------
//  Randomness
// --------------------------------------------------------------------------

extern "C" {

// Called in the EthernetClass constructor.
[[gnu::weak]]
void qnethernet_init_rand() {
  // Example seed:
  // std::srand(std::time(nullptr));
// #warning "Need srand() initialization somewhere"
  std::srand(sys_now());
}

// Gets a 32-bit random number for LWIP_RAND().
[[gnu::weak]]
uint32_t qnethernet_rand() {
  return qindesign::security::RandomDevice::instance()();
}

}  // extern "C"
