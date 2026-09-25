// G2CHK-172: HTTP/2 frame/header pools live on the heap per thread, not in
// static TLS.
#include "boltapi/http/http2_connection.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <thread>

using namespace bolt::api::http2;

TEST(Http2BufferPool, PoolsArePerThreadHeapBlocks) {
    H2FramePool*  f = h2_frame_pool();
    H2HeaderPool* h = h2_header_pool();
    ASSERT_NE(f, nullptr);
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(f, h2_frame_pool());
    EXPECT_EQ(h, h2_header_pool());
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(f) % 64u, 0u);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(h) % 64u, 0u);

    H2FramePool* other = nullptr;
    std::thread t([&other] { other = h2_frame_pool(); });
    t.join();
    ASSERT_NE(other, nullptr);
    EXPECT_NE(other, f);
}

TEST(Http2BufferPool, AcquireExhaustReleaseReuse) {
    BufferPool<16384, 16> pool;
    std::uint8_t* bufs[H2_FRAME_BUFFER_COUNT] = {};
    for (std::size_t i = 0; i < H2_FRAME_BUFFER_COUNT; ++i) {
        bufs[i] = pool.acquire();
        ASSERT_NE(bufs[i], nullptr) << i;
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(bufs[i]) % 64u, 0u);
        bufs[i][0] = static_cast<std::uint8_t>(i);
        bufs[i][H2_FRAME_BUFFER_SIZE - 1] = static_cast<std::uint8_t>(i);
    }
    EXPECT_EQ(pool.acquire(), nullptr);
    pool.release(bufs[7]);
    EXPECT_EQ(pool.acquire(), bufs[7]);
    for (std::size_t i = 0; i < H2_FRAME_BUFFER_COUNT; ++i) pool.release(bufs[i]);

    BufferPool<8192, 8> hp;
    std::uint8_t* hb = hp.acquire();
    ASSERT_NE(hb, nullptr);
    hp.release(hb);
    EXPECT_EQ(hp.acquire(), hb);
    hp.release(hb);
}
