// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// Public umbrella header for vianium-mtproxy's secret parser.
//
// Consumers in sibling repos (vianium-mtproto, vianigram) include this
// stable path; the implementation lives under src/. Internal callers
// inside this repo include the src/ path directly.

#include "../../../src/domain/value_objects/mt_proxy_secret.h"
