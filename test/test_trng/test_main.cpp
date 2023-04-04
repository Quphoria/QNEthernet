// SPDX-FileCopyrightText: (c) 2023 Shawn Silverman <shawn@pobox.com>
// SPDX-License-Identifier: MIT

// test_main.cpp tests the entropy functions.
// This file is part of the QNEthernet library.

#include <Arduino.h>
#include <security/entropy.h>
#include <unity.h>

// --------------------------------------------------------------------------
//  Main Program
// --------------------------------------------------------------------------

// Pre-test setup. This is run before every test.
void setUp() {
}

// Post-test teardown. This is run after every test.
void tearDown() {
}

// Tests that the feature is active.
static void test_active() {
  TEST_ASSERT_TRUE_MESSAGE(trng_is_started(), "Expected started");
}

// Tests that the feature is inactive.
static void test_inactive() {
  TEST_ASSERT_FALSE_MESSAGE(trng_is_started(), "Expected not started");
}

// Tests data-available.
static void test_available() {
  // Assume we're going to read full entropy
  delay(100);  // Give it time to collect entropy
  TEST_ASSERT_EQUAL_MESSAGE(64, trng_available(), "Expected full entropy");
}

// Tests data access.
static void test_data() {
  uint8_t b[64];
  TEST_ASSERT_EQUAL_MESSAGE(1, trng_data(b, 1), "Expected 1-byte read");
  TEST_ASSERT_EQUAL_MESSAGE(63, trng_available(), "Expected full entropy");
  TEST_ASSERT_EQUAL_MESSAGE(63, trng_data(&b[1], 63), "Expected 63-byte read");
  TEST_ASSERT_EQUAL_MESSAGE(0, trng_available(), "Expected empty entropy");
}

// Main program setup.
void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 4000) {
    // Wait for Serial
  }

  // NOTE!!! Wait for >2 secs
  // if board doesn't support software reset via Serial.DTR/RTS
  delay(2000);

  if (CrashReport) {
    Serial.println(CrashReport);
  }

  trng_init();

  UNITY_BEGIN();
  RUN_TEST(test_active);
  RUN_TEST(test_available);
  RUN_TEST(test_data);
  trng_deinit();
  RUN_TEST(test_inactive);
  UNITY_END();
}

// Main program loop.
void loop() {
}
