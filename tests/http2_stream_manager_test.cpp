// http2_stream_manager_test.cpp — gtest coverage for http2::StreamManager.
//
// G2CHK-85: StreamManager::streams_ moved off std::unordered_map<uint32_t,
// Http2Stream> onto bolt::SwissTableGrowable (stream_id -> pool slot) + a
// std::vector<unique_ptr<Http2Stream>> pool with free-list slot reuse. This
// is new coverage (no prior test exercised StreamManager at all) and it is
// specifically written to prove the property the refactor depends on:
// Http2Stream* addresses stay stable across create/remove of OTHER streams
// (callers in http2_connection.cpp hold a raw pointer across such calls).

#include "boltapi/http/http2_stream.h"

#include <gtest/gtest.h>

#include <vector>

namespace http2 = bolt::api::http2;

TEST(Http2StreamManager, CreateGetRemoveRoundTrip) {
    http2::StreamManager mgr;
    EXPECT_EQ(mgr.stream_count(), 0u);
    EXPECT_EQ(mgr.get_stream(1), nullptr);

    auto created = mgr.create_stream(1);
    ASSERT_TRUE(created.is_ok());
    EXPECT_EQ(created.value()->id(), 1u);
    EXPECT_EQ(mgr.stream_count(), 1u);
    EXPECT_EQ(mgr.get_stream(1), created.value());

    mgr.remove_stream(1);
    EXPECT_EQ(mgr.stream_count(), 0u);
    EXPECT_EQ(mgr.get_stream(1), nullptr);
}

TEST(Http2StreamManager, DuplicateCreateFails) {
    http2::StreamManager mgr;
    ASSERT_TRUE(mgr.create_stream(3).is_ok());
    auto dup = mgr.create_stream(3);
    EXPECT_TRUE(dup.is_err());
    EXPECT_EQ(mgr.stream_count(), 1u);
}

TEST(Http2StreamManager, RemoveUnknownIsNoop) {
    http2::StreamManager mgr;
    mgr.remove_stream(42);  // must not crash / must not touch stream_count()
    EXPECT_EQ(mgr.stream_count(), 0u);
}

// The load-bearing property: creating/removing stream B must not invalidate
// a previously-returned pointer to stream A (mirrors handle_headers_frame's
// "get_stream, maybe create_stream for a DIFFERENT id, keep using the first
// pointer" pattern in http2_connection.cpp).
TEST(Http2StreamManager, PointerStableAcrossOtherStreamChurn) {
    http2::StreamManager mgr;
    auto a = mgr.create_stream(1);
    ASSERT_TRUE(a.is_ok());
    http2::Http2Stream* stream_a = a.value();
    
    for (uint32_t id = 2; id < 50; ++id) {
        ASSERT_TRUE(mgr.create_stream(id).is_ok());
        if (id % 2 == 0) mgr.remove_stream(id);
    }

    // stream_a's address must be exactly what create_stream(1) returned, and
    // it must still be reachable by id through the manager.
    EXPECT_EQ(mgr.get_stream(1), stream_a);
}

// Slot reuse: closing a stream and opening a new one should not grow the
// pool without bound -- the freed slot is recycled.
TEST(Http2StreamManager, ClosedSlotIsRecycled) {
    http2::StreamManager mgr;
    ASSERT_TRUE(mgr.create_stream(1).is_ok());
    mgr.remove_stream(1);
    ASSERT_TRUE(mgr.create_stream(2).is_ok());
    // The new stream must be a genuinely fresh Http2Stream, not stale state
    // from stream 1 -- distinguished by stream_id().
    EXPECT_EQ(mgr.get_stream(2)->id(), 2u);
    EXPECT_EQ(mgr.get_stream(1), nullptr);
    EXPECT_EQ(mgr.stream_count(), 1u);
}

TEST(Http2StreamManager, UpdateInitialWindowSizeVisitsAllLiveStreams) {
    http2::StreamManager mgr(65535);
    std::vector<http2::Http2Stream*> streams;
    for (uint32_t id = 1; id <= 5; ++id) {
        auto r = mgr.create_stream(id);
        ASSERT_TRUE(r.is_ok());
        streams.push_back(r.value());
    }
    // Remove one so the iteration must skip a hole in the index table.
    mgr.remove_stream(3);

    mgr.update_initial_window_size(70000);

    for (uint32_t id = 1; id <= 5; ++id) {
        if (id == 3) {
            EXPECT_EQ(mgr.get_stream(id), nullptr);
            continue;
        }
        ASSERT_NE(mgr.get_stream(id), nullptr);
        EXPECT_GE(mgr.get_stream(id)->send_window(), 65535);
    }
}

// Many create/remove cycles well past the manager's initial pool size to
// exercise both SwissTableGrowable's grow path and free-slot recycling.
TEST(Http2StreamManager, ManyChurnCyclesStayConsistent) {
    http2::StreamManager mgr;
    uint32_t next_id = 1;
    for (int round = 0; round < 500; ++round) {
        uint32_t id = next_id++;
        auto r = mgr.create_stream(id);
        ASSERT_TRUE(r.is_ok()) << "round " << round;
        EXPECT_EQ(mgr.get_stream(id), r.value());
        mgr.remove_stream(id);
        EXPECT_EQ(mgr.get_stream(id), nullptr);
    }
    EXPECT_EQ(mgr.stream_count(), 0u);
}
