// SPDX-FileCopyrightText: (c) 2024 Shawn Silverman <shawn@pobox.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// lwip_driver.c implements Ethernet interface functions.
// This file is part of the QNEthernet library.

#include "lwip_driver.h"

// C includes
#include <string.h>
#include <util/atomic.h>

#include "lwip/autoip.h"
#include "lwip/dhcp.h"
#include "lwip/etharp.h"
#include "lwip/init.h"
#include "lwip/prot/ieee.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"

// --------------------------------------------------------------------------
//  Internal Variables
// --------------------------------------------------------------------------

// Current MAC address.
static uint8_t s_mac[ETH_HWADDR_LEN];

// netif state
static struct netif s_netif = { .name = {'e', '0'} };
static bool s_isNetifAdded  = false;
NETIF_DECLARE_EXT_CALLBACK(netif_callback)/*;*/

// Structs for avoiding memory allocation
#if LWIP_DHCP
static struct dhcp s_dhcp;
#endif  // LWIP_DHCP
#if LWIP_AUTOIP
static struct autoip s_autoip;
#endif  // LWIP_AUTOIP

#if QNETHERNET_ENABLE_IEEE1588_SUPPORT
// IEEE 1588
volatile uint32_t ieee1588Seconds = 0;  // Since the timer was started
volatile bool doTimestampNext = false;
volatile bool hasTxTimestamp = false;
volatile struct timespec txTimestamp = {0, 0};
#endif // QNETHERNET_ENABLE_IEEE1588_SUPPORT

// --------------------------------------------------------------------------
//  Internal Functions
// --------------------------------------------------------------------------

// Outputs the given pbuf to the driver.
static err_t link_output(struct netif *netif, struct pbuf *p) {
  LWIP_UNUSED_ARG(netif);

  if (p == NULL) {
    return ERR_ARG;
  }

  return driver_output(p);
}

// Initializes the netif.
static err_t init_netif(struct netif *netif) {
  if (netif == NULL) {
    return ERR_ARG;
  }

  netif->linkoutput = link_output;
#if LWIP_IPV4
  netif->output     = etharp_output;
#endif  // LWIP_IPV4
  netif->mtu        = MTU;
  netif->flags = 0
                 | NETIF_FLAG_BROADCAST
#if LWIP_IPV4
                 | NETIF_FLAG_ETHARP
#endif  // LWIP_IPV4
                 | NETIF_FLAG_ETHERNET
#if LWIP_IGMP
                 | NETIF_FLAG_IGMP
#endif  // LWIP_IGMP
                 ;

  memcpy(netif->hwaddr, s_mac, ETH_HWADDR_LEN);
  netif->hwaddr_len = ETH_HWADDR_LEN;

#if LWIP_NETIF_HOSTNAME
  netif_set_hostname(netif, NULL);
#endif  // LWIP_NETIF_HOSTNAME

  return ERR_OK;
}

#if LWIP_IGMP && !QNETHERNET_ENABLE_PROMISCUOUS_MODE
// Multicast filter for letting the hardware know which packets to let in.
static err_t multicast_filter(struct netif *netif, const ip4_addr_t *group,
                              enum netif_mac_filter_action action) {
  LWIP_UNUSED_ARG(netif);

  bool retval = true;
  switch (action) {
    case NETIF_ADD_MAC_FILTER:
      retval = enet_join_group(group);
      break;
    case NETIF_DEL_MAC_FILTER:
      retval = enet_leave_group(group);
      break;
    default:
      break;
  }
  return retval ? ERR_OK : ERR_USE;
      // ERR_USE seems like the best fit of the choices
      // Next best seems to be ERR_IF
}
#endif  // LWIP_IGMP && !QNETHERNET_ENABLE_PROMISCUOUS_MODE

#if QNETHERNET_INTERNAL_END_STOPS_ALL
// Removes the current netif, if any.
static void remove_netif() {
  if (s_isNetifAdded) {
    netif_set_default(NULL);
    netif_remove(&s_netif);
    netif_remove_ext_callback(&netif_callback);
    s_isNetifAdded = false;
  }
}
#endif  // QNETHERNET_INTERNAL_END_STOPS_ALL

// --------------------------------------------------------------------------
//  Public Interface
// --------------------------------------------------------------------------

struct netif *enet_netif() {
  return &s_netif;
}

void enet_get_system_mac(uint8_t mac[ETH_HWADDR_LEN]) {
  if (mac != NULL) {
    driver_get_system_mac(mac);
  }
}

// This only uses the callback if the interface has not been added.
bool enet_init(const uint8_t mac[ETH_HWADDR_LEN],
               netif_ext_callback_fn callback) {
  // Sanitize the inputs
  uint8_t m[ETH_HWADDR_LEN];
  if (mac == NULL) {
    driver_get_system_mac(m);
    mac = m;
  }

  // Only execute the following code once
  static bool isFirstInit = true;
  if (isFirstInit) {
    lwip_init();
    isFirstInit = false;
  } else if (memcmp(s_mac, mac, ETH_HWADDR_LEN) != 0) {
    // First test if the MAC address has changed
    // If it's changed then remove the interface and start again

    // MAC address has changed

    // Remove any previous configuration
    // remove_netif();
    // TODO: For some reason, remove_netif() prevents further operation
  }

  memcpy(s_mac, mac, ETH_HWADDR_LEN);

  if (!driver_init(s_mac)) {
    return false;
  }

  if (!s_isNetifAdded) {
    netif_add_ext_callback(&netif_callback, callback);
    if (netif_add_noaddr(&s_netif, NULL, init_netif, ethernet_input) == NULL) {
      netif_remove_ext_callback(&netif_callback);
      return false;
    }
    netif_set_default(&s_netif);
    s_isNetifAdded = true;

    // netif_add() clears these, so re-set them
#if LWIP_DHCP
    dhcp_set_struct(&s_netif, &s_dhcp);
#endif  // LWIP_DHCP
#if LWIP_AUTOIP
    autoip_set_struct(&s_netif, &s_autoip);
#endif  // LWIP_AUTOIP

#if LWIP_IGMP && !QNETHERNET_ENABLE_PROMISCUOUS_MODE
    // Multicast filtering, to allow desired multicast packets in
    netif_set_igmp_mac_filter(&s_netif, &multicast_filter);
#endif  // LWIP_IGMP && !QNETHERNET_ENABLE_PROMISCUOUS_MODE
  } else {
    // Just set the MAC address

    memcpy(s_netif.hwaddr, s_mac, ETH_HWADDR_LEN);
    s_netif.hwaddr_len = ETH_HWADDR_LEN;

    driver_set_mac(s_mac);
  }

  return true;
}

void enet_deinit() {
  // Restore state
  memset(s_mac, 0, sizeof(s_mac));

#if QNETHERNET_ENABLE_IEEE1588_SUPPORT
  enet_ieee1588_deinit();
#endif // QNETHERNET_ENABLE_IEEE1588_SUPPORT

  // Something about stopping Ethernet and the PHY kills performance if Ethernet
  // is restarted after calling end(), so gate the following two blocks with a
  // macro for now

#if QNETHERNET_INTERNAL_END_STOPS_ALL
  remove_netif();  // TODO: This also causes issues (see notes in enet_init())
#endif  // QNETHERNET_INTERNAL_END_STOPS_ALL

  driver_deinit();
}

void enet_proc_input() {
  driver_proc_input(&s_netif);
}

void enet_poll() {
  sys_check_timeouts();
  driver_poll(&s_netif);
}

#if QNETHERNET_ENABLE_RAW_FRAME_SUPPORT
bool enet_output_frame(const uint8_t *frame, size_t len) {
  if (frame == NULL || len < (6 + 6 + 2)) {  // dst + src + len/type
    return false;
  }

  // Check length depending on VLAN
  if (frame[12] == (uint8_t)(ETHTYPE_VLAN >> 8) &&
      frame[13] == (uint8_t)(ETHTYPE_VLAN)) {
    if (len < (6 + 6 + 2 + 2 + 2)) {  // dst + src + VLAN tag + VLAN info + len/type
      return false;
    }
    if (len > MAX_FRAME_LEN - 4) {  // Don't include 4-byte FCS
      return false;
    }
  } else {
    if (len > MAX_FRAME_LEN - 4 - 4) {  // Don't include 4-byte FCS and VLAN
      return false;
    }
  }

#if QNETHERNET_ENABLE_RAW_FRAME_LOOPBACK
  // Check for a loopback frame
  if (memcmp(frame, s_mac, 6) == 0) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len + ETH_PAD_SIZE, PBUF_POOL);
    if (p) {
      pbuf_take_at(p, frame, len, ETH_PAD_SIZE);
      if (s_netif.input(p, &s_netif) != ERR_OK) {
        pbuf_free(p);
      }
    }
    // TODO: Collect stats?
    return true;
  }
#endif  // QNETHERNET_ENABLE_RAW_FRAME_LOOPBACK

  return driver_output_frame(frame, len);
}
#endif  // QNETHERNET_ENABLE_RAW_FRAME_SUPPORT

// --------------------------------------------------------------------------
//  MAC Address Filtering
// --------------------------------------------------------------------------

#if !QNETHERNET_ENABLE_PROMISCUOUS_MODE && LWIP_IPV4

// Joins or leaves a multicast group. The flag should be true to join and false
// to leave. This returns whether successful.
static bool enet_join_notleave_group(const ip4_addr_t *group, bool flag) {
  if (group == NULL) {
    return false;
  }

  // Multicast MAC address.
  static uint8_t multicastMAC[ETH_HWADDR_LEN] = {
      LL_IP4_MULTICAST_ADDR_0,
      LL_IP4_MULTICAST_ADDR_1,
      LL_IP4_MULTICAST_ADDR_2,
      0,
      0,
      0,
  };

  multicastMAC[3] = ip4_addr2(group) & 0x7f;
  multicastMAC[4] = ip4_addr3(group);
  multicastMAC[5] = ip4_addr4(group);

  return driver_set_mac_address_allowed(multicastMAC, flag);
}

bool enet_join_group(const ip4_addr_t *group) {
  return enet_join_notleave_group(group, true);
}

bool enet_leave_group(const ip4_addr_t *group) {
  return enet_join_notleave_group(group, false);
}

#endif  // !QNETHERNET_ENABLE_PROMISCUOUS_MODE && LWIP_IPV4

#if QNETHERNET_ENABLE_IEEE1588_SUPPORT

// --------------------------------------------------------------------------
//  IEEE 1588 functions
// --------------------------------------------------------------------------

#define ENET_ATCR_SLAVE    ((uint32_t)(1U << 13))
#define ENET_ATCR_CAPTURE  ((uint32_t)(1U << 11))
#define ENET_ATCR_RESTART  ((uint32_t)(1U << 9))
#define ENET_ATCR_PINPER   ((uint32_t)(1U << 7))
#define ENET_ATCR_Reserved ((uint32_t)(1U << 5))  // Spec says always write a 1
#define ENET_ATCR_PEREN    ((uint32_t)(1U << 4))
#define ENET_ATCR_OFFRST   ((uint32_t)(1U << 3))
#define ENET_ATCR_OFFEN    ((uint32_t)(1U << 2))
#define ENET_ATCR_EN       ((uint32_t)(1U << 0))

#define ENET_ATCOR_COR_MASK    (0x7fffffffU)
#define ENET_ATINC_INC_MASK    (0x00007f00U)
#define ENET_ATINC_INC_CORR(n) ((uint32_t)(((n) & 0x7f) << 8))
#define ENET_ATINC_INC(n)      ((uint32_t)(((n) & 0x7f) << 0))

#define NANOSECONDS_PER_SECOND (1000 * 1000 * 1000)
#define F_ENET_TS_CLK (25 * 1000 * 1000)

#define ENET_TCSR_TMODE_MASK (0x0000003cU)
#define ENET_TCSR_TMODE(n)   ((uint32_t)(((n) & 0x0f) << 2))
#define ENET_TCSR_TPWC(n)    ((uint32_t)(((n) & 0x1f) << 11))
#define ENET_TCSR_TF         ((uint32_t)(1U << 7))

void enet_ieee1588_init() {
  ENET_ATCR = ENET_ATCR_RESTART | ENET_ATCR_Reserved;  // Reset timer
  ENET_ATPER = NANOSECONDS_PER_SECOND;                 // Wrap at 10^9
  ENET_ATINC = ENET_ATINC_INC(NANOSECONDS_PER_SECOND / F_ENET_TS_CLK);
  ENET_ATCOR = 0;                                      // Start with no corr.
  while ((ENET_ATCR & ENET_ATCR_RESTART) != 0) {
    // Wait for bit to clear before being able to write to ATCR
  }

  // Reset the seconds counter to zero
  ieee1588Seconds = 0;

  // Enable the timer and periodic event
  ENET_ATCR = ENET_ATCR_PINPER | ENET_ATCR_Reserved | ENET_ATCR_PEREN |
              ENET_ATCR_EN;

  ENET_EIMR |= ENET_EIMR_TS_AVAIL | ENET_EIMR_TS_TIMER;
}

void enet_ieee1588_deinit() {
  ENET_EIMR &= ~(ENET_EIMR_TS_AVAIL | ENET_EIMR_TS_TIMER);
  ENET_ATCR = ENET_ATCR_Reserved;
}

bool enet_ieee1588_is_enabled() {
  return ((ENET_ATCR & ENET_ATCR_EN) != 0);
}

bool enet_ieee1588_read_timer(struct timespec *t) {
  if (t == NULL) {
    return false;
  }

  ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
    t->tv_sec = ieee1588Seconds;

    ENET_ATCR |= ENET_ATCR_CAPTURE;
    while ((ENET_ATCR & ENET_ATCR_CAPTURE) != 0) {
      // Wait for bit to clear
    }
    t->tv_nsec = ENET_ATVR;

    // The timer could have wrapped while we were doing stuff
    // Leave the interrupt set so that our internal timer will catch it
    if ((ENET_EIR & ENET_EIR_TS_TIMER) != 0) {
      t->tv_sec++;
    }
  }

  return true;
}

bool enet_ieee1588_write_timer(const struct timespec *t) {
  if (t == NULL) {
    return false;
  }

  ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
    ieee1588Seconds = t->tv_sec;
    ENET_ATVR = t->tv_nsec;
  }

  return true;
}

void enet_ieee1588_timestamp_next_frame() {
  doTimestampNext = true;
}

bool enet_ieee1588_read_and_clear_tx_timestamp(struct timespec *timestamp) {
  ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
    if (hasTxTimestamp) {
      hasTxTimestamp = false;
      if (timestamp != NULL) {
        timestamp->tv_sec = txTimestamp.tv_sec;
        timestamp->tv_nsec = txTimestamp.tv_nsec;
      }
      return true;
    }
  }
  return false;
}

bool enet_ieee1588_adjust_timer(uint32_t corrInc, uint32_t corrPeriod) {
  if (corrInc >= 128 || corrPeriod >= (1U << 31)) {
    return false;
  }
  CLRSET(ENET_ATINC, ENET_ATINC_INC_MASK, ENET_ATINC_INC(corrInc));
  ENET_ATCOR = corrPeriod | ENET_ATCOR_COR_MASK;
  return true;
}

bool enet_ieee1588_adjust_freq(int nsps) {
  if (nsps == 0) {
    ENET_ATCOR = 0;
    return true;
  }

  uint32_t inc = NANOSECONDS_PER_SECOND / F_ENET_TS_CLK;

  if (nsps < 0) {
    // Slow down
    inc--;
    nsps = -nsps;
  } else {
    // Speed up
    inc++;
  }
  return enet_ieee1588_adjust_timer(inc, F_ENET_TS_CLK / nsps);
}

// Channels

static volatile uint32_t *tcsrReg(int channel) {
  switch (channel) {
    case 0: return &ENET_TCSR0;
    case 1: return &ENET_TCSR1;
    case 2: return &ENET_TCSR2;
    case 3: return &ENET_TCSR3;
    default:
      return NULL;
  }
}

static volatile uint32_t *tccrReg(int channel) {
  switch (channel) {
    case 0: return &ENET_TCCR0;
    case 1: return &ENET_TCCR1;
    case 2: return &ENET_TCCR2;
    case 3: return &ENET_TCCR3;
    default:
      return NULL;
  }

}

bool enet_ieee1588_set_channel_mode(int channel, int mode) {
  switch (mode) {
    case 14:  // kTimerChannelPulseLowOnCompare
    case 15:  // kTimerChannelPulseHighOnCompare
    case 12:  // Reserved
    case 13:  // Reserved
      return false;
    default:
      if (mode < 0 || 0x0f < mode) {
        return false;
      }
      break;
  }

  volatile uint32_t *tcsr = tcsrReg(channel);
  if (tcsr == NULL) {
    return false;
  }

  *tcsr = 0;
  while ((*tcsr & ENET_TCSR_TMODE_MASK) != 0) {
    // Check until the channel is disabled
  }
  *tcsr = ENET_TCSR_TMODE(mode);

  return true;
}

bool enet_ieee1588_set_channel_output_pulse_width(int channel,
                                                  int mode,
                                                  int pulseWidth) {
  switch (mode) {
    case 14:  // kTimerChannelPulseLowOnCompare
    case 15:  // kTimerChannelPulseHighOnCompare
      break;
    default:
      return true;
  }

  if (pulseWidth < 1 || 32 < pulseWidth) {
    return false;
  }

  volatile uint32_t *tcsr = tcsrReg(channel);
  if (tcsr == NULL) {
    return false;
  }

  *tcsr = 0;
  while ((*tcsr & ENET_TCSR_TMODE_MASK) != 0) {
    // Check until the channel is disabled
  }
  *tcsr = ENET_TCSR_TMODE(mode) | ENET_TCSR_TPWC(pulseWidth - 1);

  return true;
}

bool enet_ieee1588_set_channel_compare_value(int channel, uint32_t value) {
  volatile uint32_t *tccr = tccrReg(channel);
  if (tccr == NULL) {
    return false;
  }
  *tccr = value;
  return true;
}

bool enet_ieee1588_get_and_clear_channel_status(int channel) {
  volatile uint32_t *tcsr = tcsrReg(channel);
  if (tcsr == NULL) {
    return false;
  }
  if ((*tcsr & ENET_TCSR_TF) != 0) {
    *tcsr |= ENET_TCSR_TF;
    ENET_TGSR = (1 << channel);
    return true;
  } else {
    return false;
  }
}

#endif QNETHERNET_ENABLE_IEEE1588_SUPPORT