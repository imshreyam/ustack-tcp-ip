#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "ustack/core/timer.h"
#include "ustack/net/tcp_types.h"
#include "ustack/util/bytes.h"

namespace ustack {

class TcpLayer;

// One TCP connection: the RFC 793 state machine plus
//   * retransmission with RTT-based RTO (RFC 6298) and Karn's algorithm,
//   * sliding-window flow control (receive buffer + zero-window probing),
//   * out-of-order segment buffering,
//   * congestion control: slow start, congestion avoidance, fast retransmit.
//
// The API is event driven (like lwIP's raw API): the app registers callbacks
// and calls send()/recv()/close() from anywhere on the event-loop thread,
// including from inside those callbacks.
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
    enum class CloseReason { Normal, Reset, Timeout, Aborted };
    using AcceptHandler = std::function<void(std::shared_ptr<TcpConnection>)>;

    static constexpr std::size_t kReceiveBufferSize = 65535;  // no window scaling, so max 64 KiB
    static constexpr std::size_t kSendBufferSize = 4 * 1024 * 1024;
    static constexpr std::uint16_t kDefaultMss = 536;  // RFC 1122 default when no MSS option is sent
    static constexpr Duration kInitialRto = std::chrono::seconds(1);
    static constexpr Duration kMinRto = std::chrono::milliseconds(200);  // Linux's floor (RFC 6298 says 1s)
    static constexpr Duration kMaxRto = std::chrono::seconds(60);
    static constexpr int kMaxRetransmits = 8;
    static constexpr int kMaxSynRetransmits = 5;
    static constexpr Duration kMsl = std::chrono::seconds(5);  // shortened for demos; RFC 793 uses 2 minutes

    TcpConnection(TcpLayer& layer, const TcpTuple& tuple);
    ~TcpConnection();

    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    // ---- application API -------------------------------------------------

    // Queues data for sending; returns how many bytes fit in the send buffer.
    std::size_t send(ByteView data);
    std::size_t send(std::string_view text) { return send(as_bytes(text)); }

    // Takes up to `max_bytes` bytes out of the receive buffer.
    Bytes recv(std::size_t max_bytes = std::numeric_limits<std::size_t>::max());
    std::size_t available() const noexcept { return recv_buffer_.size(); }

    void close();  // graceful: send FIN after queued data
    void abort();  // immediate: send RST

    TcpState state() const noexcept { return state_; }
    const TcpTuple& tuple() const noexcept { return tuple_; }
    bool peer_closed() const noexcept { return peer_fin_received_; }
    std::size_t unacknowledged_bytes() const noexcept { return send_buffer_.size(); }

    // Called when an active open completes.
    void set_on_connected(std::function<void()> cb) { on_connected_ = std::move(cb); }
    // Called when new in-order data is available to recv().
    void set_on_data(std::function<void()> cb) { on_data_ = std::move(cb); }
    // Called when the peer has sent FIN (no more data will arrive).
    void set_on_peer_closed(std::function<void()> cb) { on_peer_closed_ = std::move(cb); }
    // Called once when the connection reaches CLOSED for any reason.
    void set_on_closed(std::function<void(CloseReason)> cb) { on_closed_ = std::move(cb); }

    // ---- used by TcpLayer ------------------------------------------------

    void open_passive(const TcpSegment& syn, AcceptHandler on_accept);
    void open_active();
    void handle_segment(const TcpSegment& seg);

private:
    // state machine pieces
    void handle_syn_sent(const TcpSegment& seg);
    bool segment_acceptable(const TcpSegment& seg) const;
    bool process_ack(const TcpSegment& seg);
    void process_payload(const TcpSegment& seg, bool& data_arrived, bool& fin_arrived);
    void handle_fin();
    void establish();
    void enter_time_wait();
    void enter_closed(CloseReason reason);
    void set_state(TcpState next);

    // sending
    void output(bool force_probe = false);
    std::uint32_t send_segment_at(std::uint32_t seq, std::uint32_t room);
    void send_syn();
    void send_ack();
    std::uint32_t acceptable_seq() const noexcept;
    void transmit(std::uint32_t seq, std::uint8_t flags, ByteView payload, bool with_mss = false);
    void on_new_ack(std::uint32_t ack);
    void on_duplicate_ack();
    void on_retransmit_timeout();
    void arm_retransmit_timer();
    void update_rto(Duration sample);
    void update_rto_from_estimates();

    // receiving
    void store_out_of_order(std::uint32_t seq, ByteView data);
    void drain_out_of_order();

    std::uint32_t receive_window() const noexcept;
    std::uint32_t data_end() const noexcept {
        return send_buffer_seq_ + static_cast<std::uint32_t>(send_buffer_.size());
    }
    bool fin_acked() const noexcept { return fin_queued_ && send_buffer_.empty() && snd_una_ == send_buffer_seq_ + 1; }
    bool can_send_data() const noexcept;
    bool can_receive_data() const noexcept;
    bool has_unsent() const noexcept;

    TcpLayer& layer_;
    TcpTuple tuple_;
    TcpState state_ = TcpState::Closed;

    AcceptHandler on_accept_;
    std::function<void()> on_connected_;
    std::function<void()> on_data_;
    std::function<void()> on_peer_closed_;
    std::function<void(CloseReason)> on_closed_;

    // --- send sequence space (RFC 793 3.2) ---
    std::uint32_t iss_ = 0;      // initial send sequence number
    std::uint32_t snd_una_ = 0;  // oldest unacknowledged sequence number
    std::uint32_t snd_nxt_ = 0;  // next sequence number to send
    std::uint32_t snd_max_ = 0;  // highest sequence number sent so far (snd_nxt_ rewinds on timeout)
    std::uint32_t snd_wnd_ = 0;  // peer's advertised receive window
    std::uint32_t snd_wl1_ = 0;  // seq of the segment used for the last window update
    std::uint32_t snd_wl2_ = 0;  // ack of the segment used for the last window update
    std::deque<std::uint8_t> send_buffer_;  // unacked + unsent data; front byte has seq send_buffer_seq_
    std::uint32_t send_buffer_seq_ = 0;
    bool fin_queued_ = false;  // app called close(); FIN follows the last data byte
    std::uint32_t mss_ = kDefaultMss;

    // --- congestion control ---
    std::uint32_t cwnd_ = 0;
    std::uint32_t ssthresh_ = 65535;
    int dup_acks_ = 0;

    // --- retransmission / RTT ---
    Duration rto_ = kInitialRto;
    std::optional<Duration> srtt_;
    Duration rttvar_{};
    bool rtt_timing_ = false;
    std::uint32_t rtt_seq_ = 0;
    TimePoint rtt_start_{};
    int retransmits_ = 0;

    // --- receive sequence space ---
    std::uint32_t irs_ = 0;      // initial receive sequence number
    std::uint32_t rcv_nxt_ = 0;  // next sequence number expected
    std::deque<std::uint8_t> recv_buffer_;
    std::vector<std::pair<std::uint32_t, Bytes>> out_of_order_;
    std::size_t out_of_order_bytes_ = 0;
    std::optional<std::uint32_t> pending_fin_seq_;  // FIN seen beyond a hole
    bool peer_fin_received_ = false;
    std::uint32_t last_advertised_window_ = 0;
    bool ack_pending_ = false;

    Timer retransmit_timer_;
    Timer persist_timer_;
    Timer time_wait_timer_;
};

const char* to_string(TcpConnection::CloseReason reason);

}  // namespace ustack
