// SPDX-FileCopyrightText: (c) 2021-2024 Shawn Silverman <shawn@pobox.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// lwip_driver.h defines Ethernet interface functions.
// Based on code from manitou48 and others:
// https://github.com/PaulStoffregen/teensy41_ethernet
// This file is part o  f the QNEthernet library.

#pragma once

// C includes
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ethernet.h"
#include "qnethernet_opts.h"

// Requirements for driver-specific headers:
// 1. Define MTU
// 2. Define MAX_FRAME_LEN (including the 4-byte FCS (frame check sequence))

// How to create a driver:
// 1. Create a header that defines MTU and MAX_FRAME_LEN. Don't forget to use
//    either `#pragma once` or a #define guard.
// 2. Create driver source and include lwip_driver.h. Implement all the
//    `driver_x()` functions. It can be written in either C or C++. If C++ then
//    make sure to use `extern "C"` around those functions.
// 3. Adjust the following driver selection logic to define an appropriate macro
//    (such as INTERNAL_DRIVER_Y) when the desired driver condition
//    is satisfied.
// 4. Include your driver header in the correct place in the logic below.
// 5. In your driver source, gate the whole file(s) on the macro you chose
//    above. Of course, test the macro after the lwip_driver.h include.
//    (Example: INTERNAL_DRIVER_Y)
// 6. Update lwipopts.h with appropriate values for your driver.
// 7. Optionally update EthernetClass::hardwareStatus() to return an appropriate
//    enum value. If no change is made, the default 'EthernetOtherHardware' will
//    be returned if hardware is found (driver_has_hardware() returns true).

// Select a driver
#if defined(QNETHERNET_DRIVER_W5500)
#include "drivers/driver_w5500.h"
#define QNETHERNET_INTERNAL_DRIVER_W5500
#elif defined(ARDUINO_TEENSY41)
#include "drivers/driver_teensy41.h"
#define QNETHERNET_INTERNAL_DRIVER_TEENSY41
#else
#include "drivers/driver_unsupported.h"
#define QNETHERNET_INTERNAL_DRIVER_UNSUPPORTED
#endif  // Driver selection

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// --------------------------------------------------------------------------
//  Driver Interface
// --------------------------------------------------------------------------

// It can be assumed that any parameters passed in will not be NULL.

// Returns if the hardware hasn't yet been probed.
bool driver_is_unknown();

// Returns whether the link state is detectable. This will return true if the
// hardware is capable of detecting a link and false otherwise.
bool driver_is_link_state_detectable();

// Gets the built-in Ethernet MAC address.
//
// For systems without a built-in address, this should retrieve some default.
void driver_get_system_mac(uint8_t mac[ETH_HWADDR_LEN]);

// Sets the internal MAC address.
void driver_set_mac(const uint8_t mac[ETH_HWADDR_LEN]);

// Determines if there's Ethernet hardware. If the hardware hasn't yet been
// probed (driver_is_unknown() would return 'true'), then this will check
// the hardware.
bool driver_has_hardware();

// Sets the SPI chip select pin given in Ethernet.init(). The pin will be -1 if
// it has not been initialized.
void driver_set_chip_select_pin(int pin);

// Does low-level initialization. This returns whether the initialization
// was successful.
bool driver_init(const uint8_t mac[ETH_HWADDR_LEN]);

// Uninitializes the driver.
void driver_deinit();

// Processes any input and passes any received frames to the netif.
void driver_proc_input(struct netif *netif);

// Polls anything that needs to be polled, for example, the link status.
void driver_poll(struct netif *netif);

// Returns the link speed in Mbps. The value is only valid if the link is up.
int driver_link_speed();

// Returns the link duplex mode, true for full and false for half. The value is
// only valid if the link is up.
bool driver_link_is_full_duplex();

// Returns whether a crossover cable is detected. The value is only valid if the
// link is up.
bool driver_link_is_crossover();

// Outputs the given pbuf data.
//
// Note that the data will already contain any extra ETH_PAD_SIZE bytes.
err_t driver_output(struct pbuf *p);

#if QNETHERNET_ENABLE_RAW_FRAME_SUPPORT
// Outputs a raw Ethernet frame and returns whether successful.
//
// This should add any extra padding bytes given by ETH_PAD_SIZE.
bool driver_output_frame(const uint8_t *frame, size_t len);
#endif  // QNETHERNET_ENABLE_RAW_FRAME_SUPPORT

#if !QNETHERNET_ENABLE_PROMISCUOUS_MODE

// Allows or disallows frames addressed to the specified MAC address. This is
// not meant to be used for joining or leaving a multicast group at the IP
// layer; use the IP stack for that.
//
// Because the underlying system might use a hash of the MAC address, it's
// possible for there to be collisions. This means that it's not always possible
// to disallow an address once it's been allowed.
//
// This returns true if adding or removing the MAC was successful. If an address
// has a collision, then it can't be removed and this will return false. This
// will also return false if 'mac' is NULL. Otherwise, this will return true.
//
// Note that this function may be passed a NULL MAC address.
bool driver_set_mac_address_allowed(const uint8_t mac[ETH_HWADDR_LEN],
                                    bool allow);

#endif  // !QNETHERNET_ENABLE_PROMISCUOUS_MODE

// --------------------------------------------------------------------------
//  Public Interface
// --------------------------------------------------------------------------

// Returns the MTU.
inline int enet_get_mtu() {
  return MTU;
}

// Returns the maximum frame length. This includes the 4-byte FCS (frame
// check sequence).
inline int enet_get_max_frame_len() {
  return MAX_FRAME_LEN;
}

// Gets the built-in Ethernet MAC address. This does nothing if 'mac' is NULL.
//
// For systems without a built-in address, this should retrieve some default.
void enet_get_system_mac(uint8_t mac[ETH_HWADDR_LEN]);

// Initializes Ethernet and returns whether successful. This does not set the
// interface to "up".
//
// This may be called more than once, but if the MAC address has changed then
// the interface is first removed and then re-added.
//
// It is suggested to initialize the random number generator with
// qnethernet_hal_init_rand() before calling this.
bool enet_init(const uint8_t mac[ETH_HWADDR_LEN],
               netif_ext_callback_fn callback);

// Shuts down the Ethernet stack and driver.
void enet_deinit();

// Gets a pointer to the netif structure. This is useful for the netif callback
// before the default netif has been assigned.
struct netif *enet_netif();

// Processes any Ethernet input. This is meant to be called often by the
// main loop.
void enet_proc_input();

// Polls the stack (if needed) and Ethernet link status.
void enet_poll();

#if QNETHERNET_ENABLE_RAW_FRAME_SUPPORT
// Outputs a raw ethernet frame. This returns false if frame is NULL or if the
// length is not in the correct range. The proper range is 14-(MAX_FRAME_LEN-8)
// for non-VLAN frames and 18-(MAX_FRAME_LEN-4) for VLAN frames. Note that these
// ranges exclude the 4-byte FCS (frame check sequence).
// The frame is timestamped if `enet_timestamp_next_frame()` was called first.
//
// This returns the result of driver_output_frame(), if the frame checks pass.
bool enet_output_frame(const uint8_t *frame, size_t len);

#if QNETHERNET_ENABLE_IEEE1588_SUPPORT
// --------------------------------------------------------------------------
//  IEEE 1588 functions
// --------------------------------------------------------------------------

// Shared Variables
extern volatile uint32_t ieee1588Seconds = 0;  // Since the timer was started
extern volatile bool doTimestampNext = false;
extern volatile bool hasTxTimestamp = false;
extern volatile struct timespec txTimestamp = {0, 0};

// Initializes and enables the IEEE 1588 timer and functionality. The internal
// time is reset to zero.
void enet_ieee1588_init();

// Deinitializes and stops the IEEE 1588 timer.
void enet_ieee1588_deinit();

// Tests if the IEEE 1588 timer is enabled.
bool enet_ieee1588_is_enabled();

// Reads the IEEE 1588 timer. This returns whether successful.
//
// This will return false if the argument is NULL.
bool enet_ieee1588_read_timer(struct timespec *t);

// Writes the IEEE 1588 timer. This returns whether successful.
//
// This will return false if the argument is NULL.
bool enet_ieee1588_write_timer(const struct timespec *t);

// Tells the driver to timestamp the next transmitted frame.
void enet_ieee1588_timestamp_next_frame();

// Returns whether an IEEE 1588 transmit timestamp is available. If available
// and the parameter is not NULL then it is assigned to `*timestamp`. This
// clears the timestamp state so that a subsequent call will return false.
//
// This function is used after sending a packet having its transmit timestamp
// sent. Note that this only returns the latest value, so if a second
// timestamped packet is sent before retrieving the timestamp for the first
// then this will return the second timestamp (if already available).
bool enet_ieee1588_read_and_clear_tx_timestamp(struct timespec *timestamp);

// Directly adjust the correction increase and correction period. To adjust the
// timer in "nanoseconds per second", see `enet_ieee1588_adjust_freq`. This
// returns whether successful.
//
// This will return false if:
// 1. The correction increment is not in the range 0-127, or
// 2. The correction period is not in the range 0-(2^31-1).
bool enet_ieee1588_adjust_timer(uint32_t corrInc, uint32_t corrPeriod);

// Adjust the correction in nanoseconds per second. This uses
// `enet_ieee1588_adjust_timer()` under the hood.
bool enet_ieee1588_adjust_freq(int nsps);

// Sets the channel mode for the given channel. This does not set the output
// compare pulse modes. This returns whether successful.
//
// This will return false if:
// 1. The channel is unknown,
// 2. The mode is one of the output compare pulse modes, or
// 3. The mode is a reserved value or unknown.
bool enet_ieee1588_set_channel_mode(int channel, int mode);

// Sets the output compare pulse mode and pulse width for the given channel.
// This returns whether successful.
//
// This will return false if:
// 1. The channel is unknown,
// 2. The mode is not one of the output compare pulse modes, or
// 3. The pulse width is not in the range 1-32.
bool enet_ieee1588_set_channel_output_pulse_width(int channel,
                                                  int mode,
                                                  int pulseWidth);

// Sets the channel compare value. This returns whether successful.
//
// This will return false for an unknown channel.
bool enet_ieee1588_set_channel_compare_value(int channel, uint32_t value);

// Retrieves and then clears the status for the given channel. This will return
// false for an unknown channel.
bool enet_ieee1588_get_and_clear_channel_status(int channel);
#endif // QNETHERNET_ENABLE_IEEE1588_SUPPORT

#endif  // QNETHERNET_ENABLE_RAW_FRAME_SUPPORT

#if !QNETHERNET_ENABLE_PROMISCUOUS_MODE && LWIP_IPV4

// For joining and leaving multicast groups; these call
// driver_set_mac_address_allowed() with the MAC addresses related to the given
// multicast group. Note that this affects low-level MAC filtering and not the
// IP stack's use of multicast groups.
//
// If 'group' is NULL then these return false. Otherwise, these return the
// result of 'enet_set_mac_address_allowed()'.
bool enet_join_group(const ip4_addr_t *group);
bool enet_leave_group(const ip4_addr_t *group);

#endif  // !QNETHERNET_ENABLE_PROMISCUOUS_MODE && LWIP_IPV4

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
