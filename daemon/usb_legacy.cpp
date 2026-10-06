/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG USB

#include "daemon/usb_legacy.h"

#include "sysdeps.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parsebool.h>
#include <android-base/properties.h>
#include <asyncio/AsyncIO.h>

#include "adb.h"
#include "adb_unique_fd.h"
#include "daemon/property_monitor.h"
#include "daemon/usb_ffs.h"
#include "transport.h"
#include "types.h"

using namespace std::chrono_literals;

namespace {

constexpr int kDefaultMaxPacketSize = 512;

// One FunctionFS bulk transfer; the f_fs read and write paths split larger requests.
constexpr size_t kBulkSize = 16384;

// Buffers needed to carry MAX_PAYLOAD, plus one for a trailing zero-length packet.
constexpr size_t kNumBufs = 4 * MAX_PAYLOAD / kBulkSize + 1;

// iocb, event and context storage for one direction. A block serves one thread at a time: the
// reader thread uses one, the writer thread the other.
struct AioBlock {
    explicit AioBlock(size_t num_bufs) : iocb(num_bufs), iocbs(num_bufs), events(num_bufs) {
        for (size_t i = 0; i < num_bufs; ++i) {
            iocbs[i] = &iocb[i];
        }
        if (io_setup(num_bufs, &ctx) != 0) {
            PLOG(FATAL) << "io_setup failed";
        }
    }

    ~AioBlock() { io_destroy(ctx); }

    AioBlock(const AioBlock&) = delete;
    AioBlock& operator=(const AioBlock&) = delete;

    std::vector<struct iocb> iocb;
    std::vector<struct iocb*> iocbs;
    std::vector<struct io_event> events;
    aio_context_t ctx = 0;
};

int GetMaxPacketSize(int ffs_fd) {
    usb_endpoint_descriptor desc;
    if (ioctl(ffs_fd, FUNCTIONFS_ENDPOINT_DESC, reinterpret_cast<unsigned long>(&desc))) {
        D("could not get endpoint descriptor: %s", strerror(errno));
        return kDefaultMaxPacketSize;
    }
    return desc.wMaxPacketSize;
}

// A BlockingConnection over the FunctionFS bulk endpoints. Read and Write are each called from
// one thread; Close and Reset may be called from any thread.
struct UsbLegacyConnection : public BlockingConnection {
    UsbLegacyConnection(unique_fd control, unique_fd bulk_out, unique_fd bulk_in, bool use_aio,
                        std::promise<void> destruction_notifier)
        : control_(std::move(control)),
          bulk_out_(std::move(bulk_out)),
          bulk_in_(std::move(bulk_in)),
          destruction_notifier_(std::move(destruction_notifier)) {
        if (use_aio) {
            read_aiob_ = std::make_unique<AioBlock>(kNumBufs);
            write_aiob_ = std::make_unique<AioBlock>(kNumBufs);
        }
    }

    ~UsbLegacyConnection() override {
        LOG(INFO) << "closing functionfs transport";

        // The open thread reopens the endpoints as soon as it is notified, so release them first.
        bulk_out_.reset();
        bulk_in_.reset();
        control_.reset();
        destruction_notifier_.set_value();
    }

    bool Read(apacket* packet) override final {
        if (ReadFully(&packet->msg, sizeof(packet->msg)) != static_cast<int>(sizeof(packet->msg))) {
            PLOG(ERROR) << "remote usb: read terminated (message)";
            return false;
        }

        if (packet->msg.data_length == 0) {
            return true;
        }
        if (packet->msg.data_length > MAX_PAYLOAD) {
            LOG(ERROR) << "remote usb: read overflow (data length = " << packet->msg.data_length
                       << ")";
            return false;
        }

        packet->payload.resize(packet->msg.data_length);
        if (ReadFully(packet->payload.data(), packet->payload.size()) !=
            static_cast<int>(packet->payload.size())) {
            PLOG(ERROR) << "remote usb: read terminated (data)";
            return false;
        }
        return true;
    }

    bool Write(apacket* packet) override final {
        const size_t size = packet->msg.data_length;

        if (WriteFully(&packet->msg, sizeof(packet->msg)) != static_cast<int>(sizeof(packet->msg))) {
            PLOG(ERROR) << "remote usb: write terminated (message)";
            return false;
        }

        if (size != 0 && WriteFully(packet->payload.data(), size) != static_cast<int>(size)) {
            PLOG(ERROR) << "remote usb: write terminated (data)";
            return false;
        }
        return true;
    }

    bool DoTlsHandshake(RSA*, std::string*) override final {
        LOG(FATAL) << "TLS is not supported over USB";
        return false;
    }

    // Clears endpoint halts and points both bulk descriptors at /dev/null, so threads blocked on
    // the endpoints observe end of file and the f_fs endpoint files are released. The descriptor
    // numbers stay valid until the destructor closes them.
    void Close() override final {
        if (ioctl(bulk_in_.get(), FUNCTIONFS_CLEAR_HALT) < 0) {
            D("kick: bulk in (fd=%d) clear halt failed: %s", bulk_in_.get(), strerror(errno));
        }
        if (ioctl(bulk_out_.get(), FUNCTIONFS_CLEAR_HALT) < 0) {
            D("kick: bulk out (fd=%d) clear halt failed: %s", bulk_out_.get(), strerror(errno));
        }

        unique_fd null_fd(adb_open("/dev/null", O_WRONLY | O_CLOEXEC));
        if (null_fd < 0) {
            PLOG(ERROR) << "cannot open /dev/null to release the endpoints";
            return;
        }
        TEMP_FAILURE_RETRY(dup2(null_fd.get(), bulk_out_.get()));
        TEMP_FAILURE_RETRY(dup2(null_fd.get(), bulk_in_.get()));
    }

    void Reset() override final { Close(); }

  private:
    int ReadFully(void* data, size_t len) {
        if (read_aiob_) {
            return AioTransfer(read_aiob_.get(), bulk_out_.get(), data, len, true);
        }

        D("about to read (fd=%d, len=%zu)", bulk_out_.get(), len);
        char* buf = static_cast<char*>(data);
        const size_t total = len;
        while (len > 0) {
            ssize_t n = adb_read(bulk_out_, buf, std::min(kBulkSize, len));
            if (n < 0) {
                D("read failed (fd=%d): %s", bulk_out_.get(), strerror(errno));
                return -1;
            }
            if (n == 0) {
                errno = ECONNRESET;
                return -1;
            }
            buf += n;
            len -= n;
        }
        return total;
    }

    int WriteFully(const void* data, size_t len) {
        if (write_aiob_) {
            return AioTransfer(write_aiob_.get(), bulk_in_.get(), data, len, false);
        }

        D("about to write (fd=%d, len=%zu)", bulk_in_.get(), len);
        const char* buf = static_cast<const char*>(data);
        const size_t total = len;
        while (len > 0) {
            ssize_t n = adb_write(bulk_in_, buf, std::min(kBulkSize, len));
            if (n < 0) {
                D("write failed (fd=%d): %s", bulk_in_.get(), strerror(errno));
                return -1;
            }
            if (n == 0) {
                errno = EIO;
                return -1;
            }
            buf += n;
            len -= n;
        }
        return total;
    }

    // Submits len bytes as kBulkSize iocbs and waits for all of them. The host follows a read
    // that ends on a packet boundary with a zero-length packet, which is queued as one more iocb.
    static int AioTransfer(AioBlock* aiob, int fd, const void* data, size_t len, bool read) {
        const size_t packet_size = GetMaxPacketSize(fd);
        size_t num_bufs = (len + kBulkSize - 1) / kBulkSize;
        const char* cur = static_cast<const char*>(data);

        if (posix_madvise(const_cast<void*>(data), len, POSIX_MADV_SEQUENTIAL | POSIX_MADV_WILLNEED) <
            0) {
            D("madvise failed: %s", strerror(errno));
        }

        size_t remaining = len;
        for (size_t i = 0; i < num_bufs; ++i) {
            size_t buf_len = std::min(remaining, kBulkSize);
            io_prep(&aiob->iocb[i], fd, cur, buf_len, 0, read);
            remaining -= buf_len;
            cur += buf_len;
        }
        if (read && len != 0 && len % packet_size == 0) {
            io_prep(&aiob->iocb[num_bufs], fd, cur, packet_size, 0, read);
            ++num_bufs;
        }

        while (true) {
            if (TEMP_FAILURE_RETRY(io_submit(aiob->ctx, num_bufs, aiob->iocbs.data())) <
                static_cast<int>(num_bufs)) {
                PLOG(ERROR) << "aio: submit failed";
                return -1;
            }
            if (TEMP_FAILURE_RETRY(io_getevents(aiob->ctx, num_bufs, num_bufs, aiob->events.data(),
                                                nullptr)) < static_cast<int>(num_bufs)) {
                PLOG(ERROR) << "aio: wait failed";
                return -1;
            }
            if (num_bufs == 1 && aiob->events[0].res == -EINTR) {
                continue;
            }

            int total = 0;
            for (size_t i = 0; i < num_bufs; ++i) {
                if (aiob->events[i].res < 0) {
                    errno = -aiob->events[i].res;
                    PLOG(ERROR) << "aio: " << (read ? "read" : "write") << " failed, bufs "
                                << num_bufs;
                    return -1;
                }
                total += aiob->events[i].res;
            }
            return total;
        }
    }

    unique_fd control_;   // ep0; closing it releases the descriptors for the next open.
    unique_fd bulk_out_;  // "out" from the host's perspective: the source for adbd.
    unique_fd bulk_in_;   // "in" from the host's perspective: the sink for adbd.
    std::unique_ptr<AioBlock> read_aiob_;
    std::unique_ptr<AioBlock> write_aiob_;
    std::promise<void> destruction_notifier_;
};

void UsbLegacyOpenThread() {
    adb_thread_setname("usb legacy ffs open");

    // sys.usb.adb.disabled pauses rebinding of the gadget while the device acts as a USB host.
    static const char* kPropertyUsbDisabled = "sys.usb.adb.disabled";
    PropertyMonitor prop_mon;
    prop_mon.Add(kPropertyUsbDisabled, [](std::string value) {
        return android::base::ParseBool(value) == android::base::ParseBoolResult::kTrue;
    });

    while (true) {
        unique_fd control;
        unique_fd bulk_out;
        unique_fd bulk_in;
        if (!open_functionfs(&control, &bulk_out, &bulk_in)) {
            std::this_thread::sleep_for(1s);
            continue;
        }
        LOG(INFO) << "functionfs successfully initialized";

        if (android::base::GetBoolProperty(kPropertyUsbDisabled, false)) {
            LOG(INFO) << "pausing USB due to " << kPropertyUsbDisabled;
            prop_mon.Run();
            LOG(INFO) << "resuming USB";
        }

        // Kernels without f_fs aio_read/aio_write set sys.usb.ffs.aio_compat to use read(2) and
        // write(2); the property absent selects per-call AIO.
        const bool use_aio = !android::base::GetBoolProperty("sys.usb.ffs.aio_compat", false);

        std::promise<void> destruction_notifier;
        std::future<void> future = destruction_notifier.get_future();
        atransport* transport = new atransport();
        transport->serial = "UsbFfs";
        transport->SetConnection(std::make_unique<BlockingConnectionAdapter>(
                std::make_unique<UsbLegacyConnection>(std::move(control), std::move(bulk_out),
                                                      std::move(bulk_in), use_aio,
                                                      std::move(destruction_notifier))));
        register_transport(transport);
        future.wait();
    }
}

}  // namespace

void usb_init_legacy() {
    D("usb_init: using legacy FunctionFS");
    std::thread(UsbLegacyOpenThread).detach();
}
