/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// Starts the FunctionFS transport that moves data with blocking read(2) and write(2) on the
// bulk endpoints (or per-call kernel AIO when "sys.usb.ffs.aio_compat" is false). Kernels whose
// f_fs lacks aio_read/aio_write take this path. Runs the endpoint open loop on a detached thread.
void usb_init_legacy();
