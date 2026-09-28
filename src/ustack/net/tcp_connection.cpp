#include "ustack/net/tcp_connection.h"

#include <algorithm>

#include "ustack/net/tcp.h"
#include "ustack/util/log.h"

namespace ustack {

using namespace tcp_flag;

const char* to_string(TcpConnection::CloseReason reason) {
    switch (reason) {
        case TcpConnection::CloseReason::Normal: return "normal";
        case TcpConnection::CloseReason::Reset: return "reset by peer";
        case TcpConnection::CloseReason::Timeout: return "timed out";
        case TcpConnection::CloseReason::Aborted: return "aborted";
    }
    return "?";
}

TcpConnection::TcpConnection(TcpLayer& layer, const TcpTuple& tuple)
    : layer_(layer),
      tuple_(tuple),
      retransmit_timer_(layer.timers()),
      persist_timer_(layer.timers()),
      time_wait_timer_(layer.timers()) {}

TcpConnection::~TcpConnection() = default;

// ===========================================================================
// Opening
// ===========================================================================

void TcpConnection::open_active() {
    iss_ = layer_.generate_iss();
    snd_una_ = iss_;
    snd_nxt_ = snd_max_ = iss_ + 1;
    send_buffer_seq_ = iss_ + 1;
    set_state(TcpState::SynSent);
    send_syn();
}

void TcpConnection::open_passive(const TcpSegment& syn, AcceptHandler on_accept) {
    on_accept_ = std::move(on_accept);
    irs_ = syn.seq;
    rcv_nxt_ = syn.seq + 1;
    mss_ = std::min<std::uint32_t>(syn.mss.value_or(kDefaultMss), layer_.max_segment_size());

    iss_ = layer_.generate_iss();
    snd_una_ = iss_;
    snd_nxt_ = snd_max_ = iss_ + 1;
    send_buffer_seq_ = iss_ + 1;
    snd_wnd_ = syn.window;
    snd_wl1_ = syn.seq;
    snd_wl2_ = iss_;

    set_state(TcpState::SynReceived);
    send_syn();  // SYN-ACK
}

void TcpConnection::send_syn() {
    const std::uint8_t flags = state_ == TcpState::SynReceived ? (kSyn | kAck) : kSyn;
    transmit(iss_, flags, {}, /*with_mss=*/true);
    arm_retransmit_timer();
}

void TcpConnection::establish() {
    // Initial congestion window (RFC 5681 section 3.1).
    cwnd_ = std::min(4 * mss_, std::max(2 * mss_, 4380u));
    retransmits_ = 0;
    // A close() issued during the handshake takes effect now.
    set_state(fin_queued_ ? TcpState::FinWait1 : TcpState::Established);
}

// ===========================================================================
// Segment arrival (RFC 793 section 3.9, "SEGMENT ARRIVES")
// ===========================================================================

void TcpConnection::handle_segment(const TcpSegment& seg) {
    auto self = shared_from_this();  // keep us alive through app callbacks

    if (state_ == TcpState::Closed) return;
    if (state_ == TcpState::SynSent) {
        handle_syn_sent(seg);
        return;
    }

    // A retransmitted SYN means our SYN-ACK was lost: send it again.
    if (state_ == TcpState::SynReceived && seg.has(kSyn) && !seg.has(kAck) && seg.seq == irs_) {
        send_syn();
        return;
    }

    // 1. Sequence number check.
    if (!segment_acceptable(seg)) {
        log::debug("tcp", "{} unacceptable segment seq={} len={} (rcv_nxt={} wnd={})", tuple_, seg.seq,
                   seg.length(), rcv_nxt_, receive_window());
        if (!seg.has(kRst)) send_ack();
        // A retransmitted FIN in TIME_WAIT means our last ACK was lost: the
        // re-ACK above answers it, and the 2*MSL wait restarts (RFC 793).
        if (state_ == TcpState::TimeWait && seg.has(kFin)) {
            time_wait_timer_.arm(2 * kMsl, [this] { enter_closed(CloseReason::Normal); });
        }
        return;
    }

    // 2. RST. In TIME_WAIT it is ignored (RFC 1337: "TIME-WAIT assassination"),
    // e.g. a peer that already closed answering a stray duplicate with RST.
    if (seg.has(kRst)) {
        if (state_ == TcpState::TimeWait) return;
        log::info("tcp", "{} reset by peer in {}", tuple_, state_);
        enter_closed(CloseReason::Reset);
        return;
    }

    // 3. A SYN inside the window is an error: reset the connection.
    if (seg.has(kSyn)) {
        transmit(acceptable_seq(), kRst, {});
        enter_closed(CloseReason::Reset);
        return;
    }

    // 4. Everything past the handshake must carry an ACK.
    if (!seg.has(kAck)) return;

    bool newly_established = false;
    if (state_ == TcpState::SynReceived) {
        if (seq_lt(snd_una_, seg.ack) && seq_le(seg.ack, snd_max_)) {
            establish();
            newly_established = true;
        } else {
            layer_.transmit(tuple_, seg.ack, 0, kRst, 0, {});
            return;
        }
    }

    if (!process_ack(seg) || state_ == TcpState::Closed) return;

    // 5./6. Segment text and FIN.
    bool data_arrived = false;
    bool fin_arrived = false;
    if (can_receive_data()) process_payload(seg, data_arrived, fin_arrived);

    output();  // the ACK may have opened the window
    if (ack_pending_) send_ack();

    // Notify the application last, once all state is consistent. Callbacks are
    // copied because they may call abort(), which clears them.
    if (newly_established) {
        if (on_accept_) {
            auto cb = on_accept_;
            cb(self);
        } else if (on_connected_) {  // simultaneous open
            auto cb = on_connected_;
            cb();
        }
        if (state_ == TcpState::Closed) return;
    }
    if (data_arrived && on_data_) {
        auto cb = on_data_;
        cb();
        if (state_ == TcpState::Closed) return;
    }
    if (fin_arrived && on_peer_closed_) {
        auto cb = on_peer_closed_;
        cb();
    }
}

void TcpConnection::handle_syn_sent(const TcpSegment& seg) {
    bool ack_ok = false;
    if (seg.has(kAck)) {
        if (seq_le(seg.ack, iss_) || seq_gt(seg.ack, snd_max_)) {
            if (!seg.has(kRst)) layer_.transmit(tuple_, seg.ack, 0, kRst, 0, {});
            return;
        }
        ack_ok = true;
    }
    if (seg.has(kRst)) {
        if (ack_ok) {
            log::info("tcp", "{} connection refused", tuple_);
            enter_closed(CloseReason::Reset);
        }
        return;
    }
    if (!seg.has(kSyn)) return;

    irs_ = seg.seq;
    rcv_nxt_ = seg.seq + 1;
    mss_ = std::min<std::uint32_t>(seg.mss.value_or(kDefaultMss), layer_.max_segment_size());
    snd_wnd_ = seg.window;
    snd_wl1_ = seg.seq;
    snd_wl2_ = seg.ack;

    if (!ack_ok) {
        // Simultaneous open: both sides sent SYN. Answer with SYN-ACK.
        set_state(TcpState::SynReceived);
        send_syn();
        return;
    }

    snd_una_ = seg.ack;
    retransmit_timer_.cancel();
    rto_ = kInitialRto;  // don't carry SYN backoff into the data phase
    establish();
    send_ack();
    output();  // data queued before the connection completed
    if (on_connected_) {
        auto cb = on_connected_;
        cb();
    }
}

bool TcpConnection::segment_acceptable(const TcpSegment& seg) const {
    // RFC 793 page 69: the four cases of segment length vs. receive window.
    const std::uint32_t len = seg.length();
    const std::uint32_t wnd = receive_window();
    if (len == 0) {
        return wnd == 0 ? seg.seq == rcv_nxt_ : seq_in_window(seg.seq, rcv_nxt_, wnd);
    }
    if (wnd == 0) return false;
    return seq_in_window(seg.seq, rcv_nxt_, wnd) || seq_in_window(seg.seq + len - 1, rcv_nxt_, wnd);
}

// Returns false if processing of this segment must stop.
bool TcpConnection::process_ack(const TcpSegment& seg) {
    if (seq_gt(seg.ack, snd_max_)) {  // acknowledges something we never sent
        send_ack();
        return false;
    }

    bool window_changed = false;
    if (seq_ge(seg.ack, snd_una_)) {
        // Only take window updates from segments newer than the last one used
        // (prevents old, reordered segments from shrinking the window).
        if (seq_lt(snd_wl1_, seg.seq) || (snd_wl1_ == seg.seq && seq_le(snd_wl2_, seg.ack))) {
            window_changed = snd_wnd_ != seg.window;
            snd_wnd_ = seg.window;
            snd_wl1_ = seg.seq;
            snd_wl2_ = seg.ack;
            if (snd_wnd_ > 0) persist_timer_.cancel();
        }
    }

    if (seq_gt(seg.ack, snd_una_)) {
        on_new_ack(seg.ack);
    } else if (seg.ack == snd_una_ && seg.payload.empty() && !seg.has(kFin) && !window_changed &&
               snd_una_ != snd_max_) {
        on_duplicate_ack();
    }

    if (fin_acked()) {
        switch (state_) {
            case TcpState::FinWait1: set_state(TcpState::FinWait2); break;
            case TcpState::Closing: enter_time_wait(); break;
            case TcpState::LastAck:
                enter_closed(CloseReason::Normal);
                return false;
            default: break;
        }
    }
    return true;
}

void TcpConnection::process_payload(const TcpSegment& seg, bool& data_arrived, bool& fin_arrived) {
    std::uint32_t seq = seg.seq;
    ByteView payload = seg.payload;
    std::optional<std::uint32_t> fin_seq;
    if (seg.has(kFin)) fin_seq = seq + static_cast<std::uint32_t>(payload.size());

    if (!payload.empty()) {
        ack_pending_ = true;
        // Trim bytes we already have (retransmission overlapping old data).
        if (seq_lt(seq, rcv_nxt_)) {
            const std::uint32_t dup = rcv_nxt_ - seq;
            payload = dup >= payload.size() ? ByteView{} : payload.subspan(dup);
            seq = rcv_nxt_;
        }
        // Trim anything beyond the right edge of our window.
        const std::uint32_t right_edge = rcv_nxt_ + receive_window();
        if (!payload.empty() && seq_ge(seq, right_edge)) {
            payload = {};
            fin_seq.reset();
        } else if (!payload.empty() && payload.size() > right_edge - seq) {
            payload = payload.first(right_edge - seq);
            fin_seq.reset();
        }

        if (!payload.empty()) {
            if (seq == rcv_nxt_) {
                recv_buffer_.insert(recv_buffer_.end(), payload.begin(), payload.end());
                rcv_nxt_ += static_cast<std::uint32_t>(payload.size());
                drain_out_of_order();
                data_arrived = true;
            } else {
                store_out_of_order(seq, payload);  // ACK below will be a duplicate ACK
            }
        }
    }

    if (fin_seq) {
        ack_pending_ = true;
        if (seq_ge(*fin_seq, rcv_nxt_)) pending_fin_seq_ = *fin_seq;
    }
    if (pending_fin_seq_ && *pending_fin_seq_ == rcv_nxt_) {
        pending_fin_seq_.reset();
        rcv_nxt_ += 1;  // FIN occupies one sequence number
        handle_fin();
        fin_arrived = true;
    }
}

void TcpConnection::handle_fin() {
    peer_fin_received_ = true;
    log::debug("tcp", "{} received FIN in {}", tuple_, state_);
    switch (state_) {
        case TcpState::SynReceived:
        case TcpState::Established: set_state(TcpState::CloseWait); break;
        case TcpState::FinWait1:
            if (fin_acked()) {
                enter_time_wait();
            } else {
                set_state(TcpState::Closing);  // simultaneous close
            }
            break;
        case TcpState::FinWait2: enter_time_wait(); break;
        default: break;
    }
}

void TcpConnection::enter_time_wait() {
    set_state(TcpState::TimeWait);
    retransmit_timer_.cancel();
    persist_timer_.cancel();
    time_wait_timer_.arm(2 * kMsl, [this] { enter_closed(CloseReason::Normal); });
}

void TcpConnection::enter_closed(CloseReason reason) {
    if (state_ == TcpState::Closed) return;
    set_state(TcpState::Closed);
    retransmit_timer_.cancel();
    persist_timer_.cancel();
    time_wait_timer_.cancel();
    layer_.release(this);

    // Drop every callback so app lambdas that captured the connection don't
    // keep it alive through a reference cycle.
    auto on_closed = std::move(on_closed_);
    on_closed_ = nullptr;
    on_accept_ = nullptr;
    on_connected_ = nullptr;
    on_data_ = nullptr;
    on_peer_closed_ = nullptr;
    if (on_closed) on_closed(reason);
}

void TcpConnection::set_state(TcpState next) {
    if (next == state_) return;
    log::debug("tcp", "{} {} -> {}", tuple_, state_, next);
    state_ = next;
}

bool TcpConnection::can_send_data() const noexcept {
    switch (state_) {
        case TcpState::Established:
        case TcpState::CloseWait:
        case TcpState::FinWait1:
        case TcpState::Closing:
        case TcpState::LastAck: return true;
        default: return false;
    }
}

bool TcpConnection::can_receive_data() const noexcept {
    return state_ == TcpState::Established || state_ == TcpState::FinWait1 || state_ == TcpState::FinWait2;
}

// ===========================================================================
// Application API
// ===========================================================================

std::size_t TcpConnection::send(ByteView data) {
    switch (state_) {
        case TcpState::SynSent:
        case TcpState::SynReceived:
        case TcpState::Established:
        case TcpState::CloseWait: break;
        default: return 0;
    }
    if (fin_queued_) return 0;
    const std::size_t n = std::min(data.size(), kSendBufferSize - send_buffer_.size());
    send_buffer_.insert(send_buffer_.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(n));
    output();
    return n;
}

Bytes TcpConnection::recv(std::size_t max_bytes) {
    const std::size_t n = std::min(max_bytes, recv_buffer_.size());
    Bytes out(recv_buffer_.begin(), recv_buffer_.begin() + static_cast<std::ptrdiff_t>(n));
    recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + static_cast<std::ptrdiff_t>(n));

    // Window update: tell the peer once the window has opened meaningfully
    // (avoids "silly window syndrome" style one-byte updates).
    if (n > 0 && can_receive_data()) {
        const std::uint32_t wnd = receive_window();
        const std::uint32_t threshold = std::min<std::uint32_t>(mss_, kReceiveBufferSize / 2);
        if (wnd > last_advertised_window_ && wnd - last_advertised_window_ >= threshold) send_ack();
    }
    return out;
}

void TcpConnection::close() {
    switch (state_) {
        case TcpState::SynSent: enter_closed(CloseReason::Normal); break;
        case TcpState::SynReceived: fin_queued_ = true; break;  // FIN goes out after the handshake
        case TcpState::Established:
            fin_queued_ = true;
            set_state(TcpState::FinWait1);
            output();
            break;
        case TcpState::CloseWait:
            fin_queued_ = true;
            set_state(TcpState::LastAck);
            output();
            break;
        default: break;
    }
}

void TcpConnection::abort() {
    if (state_ == TcpState::Closed) return;
    if (state_ != TcpState::SynSent && state_ != TcpState::TimeWait) transmit(acceptable_seq(), kRst | kAck, {});
    enter_closed(CloseReason::Aborted);
}

// ===========================================================================
// Sending
// ===========================================================================

bool TcpConnection::has_unsent() const noexcept {
    return seq_lt(snd_nxt_, data_end()) || (fin_queued_ && seq_le(snd_nxt_, data_end()));
}

void TcpConnection::output(bool force_probe) {
    if (!can_send_data()) return;

    for (;;) {
        if (!has_unsent()) break;
        // Usable window = min(peer's receive window, congestion window) - bytes in flight.
        const std::uint32_t window = std::min(snd_wnd_, cwnd_);
        const std::uint32_t in_flight = snd_nxt_ - snd_una_;
        std::uint32_t room = window > in_flight ? window - in_flight : 0;
        if (room == 0 && force_probe) room = 1;  // zero-window probe: push one byte past the window
        if (room == 0) break;

        const bool new_data = snd_nxt_ == snd_max_;
        const std::uint32_t seq = snd_nxt_;
        const std::uint32_t used = send_segment_at(seq, room);
        if (used == 0) break;

        // Time one segment per RTT; never time retransmissions (Karn's algorithm).
        if (new_data && !rtt_timing_) {
            rtt_timing_ = true;
            rtt_seq_ = seq;
            rtt_start_ = layer_.timers().now();
        }
        snd_nxt_ += used;
        if (seq_gt(snd_nxt_, snd_max_)) snd_max_ = snd_nxt_;
        if (!retransmit_timer_.armed()) arm_retransmit_timer();
        force_probe = false;
    }

    // Peer's window is closed and nothing is in flight to elicit an update:
    // probe periodically so a lost window update can't deadlock us.
    if (snd_wnd_ == 0 && snd_nxt_ == snd_una_ && has_unsent() && !persist_timer_.armed()) {
        persist_timer_.arm(rto_, [this] {
            log::debug("tcp", "{} zero-window probe", tuple_);
            output(/*force_probe=*/true);
        });
    }
}

// Sends one segment starting at `seq` (new data or retransmission) using at
// most `room` sequence numbers. Returns the sequence space consumed.
std::uint32_t TcpConnection::send_segment_at(std::uint32_t seq, std::uint32_t room) {
    const std::size_t offset = seq - send_buffer_seq_;
    const std::size_t available = send_buffer_.size() > offset ? send_buffer_.size() - offset : 0;
    const std::size_t len = std::min({available, std::size_t{room}, std::size_t{mss_}});
    const bool last_data = offset + len == send_buffer_.size();
    const bool fin = fin_queued_ && last_data && len < room;
    if (len == 0 && !fin) return 0;

    std::uint8_t flags = kAck;
    if (len > 0 && last_data) flags |= kPsh;
    if (fin) flags |= kFin;

    const auto begin = send_buffer_.begin() + static_cast<std::ptrdiff_t>(offset);
    const Bytes payload(begin, begin + static_cast<std::ptrdiff_t>(len));
    if (seq_lt(seq, snd_max_)) layer_.stats().retransmitted_segments++;
    transmit(seq, flags, payload);
    return static_cast<std::uint32_t>(len) + (fin ? 1 : 0);
}

void TcpConnection::send_ack() { transmit(acceptable_seq(), kAck, {}); }

// Sequence number for segments without data (pure ACKs, RSTs). After a
// go-back-N rewind, snd_nxt_ can be *behind* what the peer already received,
// and the peer would reject a segment with such an old seq (RFC 793 p.69),
// throwing away our ACK with it. If both sides are recovering at once, that
// deadlocks. Like Linux's tcp_acceptable_seq(), use the highest sequence sent,
// clamped to the right edge of the peer's window.
std::uint32_t TcpConnection::acceptable_seq() const noexcept {
    const std::uint32_t window_end = snd_una_ + snd_wnd_;
    return seq_le(snd_max_, window_end) ? snd_max_ : window_end;
}

void TcpConnection::transmit(std::uint32_t seq, std::uint8_t flags, ByteView payload, bool with_mss) {
    const std::uint32_t window = std::min<std::uint32_t>(receive_window(), 65535);
    if (flags & kAck) {
        ack_pending_ = false;
        last_advertised_window_ = window;
    }
    const std::optional<std::uint16_t> mss =
        with_mss ? std::optional<std::uint16_t>(static_cast<std::uint16_t>(layer_.max_segment_size()))
                 : std::nullopt;
    layer_.transmit(tuple_, seq, (flags & kAck) ? rcv_nxt_ : 0, flags, static_cast<std::uint16_t>(window), payload,
                    mss);
}

void TcpConnection::on_new_ack(std::uint32_t ack) {
    const std::uint32_t acked = ack - snd_una_;

    // Release acknowledged bytes from the send buffer.
    const auto data_acked = static_cast<std::int32_t>(ack - send_buffer_seq_);
    if (data_acked > 0) {
        const std::size_t n = std::min(static_cast<std::size_t>(data_acked), send_buffer_.size());
        send_buffer_.erase(send_buffer_.begin(), send_buffer_.begin() + static_cast<std::ptrdiff_t>(n));
        send_buffer_seq_ += static_cast<std::uint32_t>(n);
    }
    snd_una_ = ack;
    if (seq_lt(snd_nxt_, snd_una_)) snd_nxt_ = snd_una_;  // after a go-back, ACK may leap ahead
    dup_acks_ = 0;
    retransmits_ = 0;

    if (rtt_timing_ && seq_gt(ack, rtt_seq_)) {
        rtt_timing_ = false;
        update_rto(layer_.timers().now() - rtt_start_);
    } else if (srtt_) {
        // New data got through, so drop any exponential backoff (as BSD does).
        // Otherwise, on a lossy path where Karn's rule rarely yields a fresh
        // sample, the RTO would stay pinned at its maximum.
        update_rto_from_estimates();
    } else {
        rto_ = kInitialRto;
    }

    // Congestion control (RFC 5681): exponential growth below ssthresh,
    // roughly one MSS per RTT above it.
    if (cwnd_ < ssthresh_) {
        cwnd_ += std::min(acked, mss_);
    } else {
        cwnd_ += std::max(1u, mss_ * mss_ / std::max(cwnd_, 1u));
    }
    cwnd_ = std::min<std::uint32_t>(cwnd_, 1u << 30);

    if (snd_una_ == snd_max_) {
        retransmit_timer_.cancel();
    } else {
        arm_retransmit_timer();
    }
}

void TcpConnection::on_duplicate_ack() {
    if (++dup_acks_ != 3) return;
    // Fast retransmit (RFC 5681 section 3.2): three duplicate ACKs strongly
    // suggest the segment at snd_una was lost while later ones arrived.
    const std::uint32_t flight = snd_max_ - snd_una_;
    ssthresh_ = std::max(flight / 2, 2 * mss_);
    cwnd_ = ssthresh_;
    rtt_timing_ = false;
    log::debug("tcp", "{} fast retransmit at seq {}", tuple_, snd_una_);
    send_segment_at(snd_una_, mss_ + 1);
    arm_retransmit_timer();
}

void TcpConnection::arm_retransmit_timer() {
    retransmit_timer_.arm(rto_, [this] { on_retransmit_timeout(); });
}

void TcpConnection::on_retransmit_timeout() {
    auto self = shared_from_this();

    if (state_ == TcpState::SynSent || state_ == TcpState::SynReceived) {
        if (++retransmits_ > kMaxSynRetransmits) {
            log::warn("tcp", "{} handshake timed out", tuple_);
            enter_closed(CloseReason::Timeout);
            return;
        }
        rto_ = std::min(rto_ * 2, kMaxRto);
        log::debug("tcp", "{} retransmitting SYN (rto now {}ms)", tuple_,
                   std::chrono::duration_cast<std::chrono::milliseconds>(rto_).count());
        layer_.stats().retransmitted_segments++;
        send_syn();
        return;
    }
    if (snd_una_ == snd_max_) return;  // everything was acknowledged meanwhile

    // Probing a zero window is not a failure, so it doesn't count towards the limit.
    if (snd_wnd_ != 0 && ++retransmits_ > kMaxRetransmits) {
        log::warn("tcp", "{} too many retransmissions; giving up", tuple_);
        transmit(acceptable_seq(), kRst | kAck, {});
        enter_closed(CloseReason::Timeout);
        return;
    }

    // Timeout = severe congestion signal: collapse cwnd to one segment and
    // back off the timer exponentially (RFC 5681 3.1, RFC 6298 5.5).
    const std::uint32_t flight = snd_max_ - snd_una_;
    ssthresh_ = std::max(flight / 2, 2 * mss_);
    cwnd_ = mss_;
    dup_acks_ = 0;
    rto_ = std::min(rto_ * 2, kMaxRto);
    rtt_timing_ = false;
    log::debug("tcp", "{} RTO: retransmitting from seq {} (rto now {}ms)", tuple_, snd_una_,
               std::chrono::duration_cast<std::chrono::milliseconds>(rto_).count());

    // Go back N: resend from the oldest unacknowledged byte.
    snd_nxt_ = snd_una_;
    output();
}

void TcpConnection::update_rto(Duration sample) {
    // RFC 6298 section 2.
    if (!srtt_) {
        srtt_ = sample;
        rttvar_ = sample / 2;
    } else {
        const Duration err = *srtt_ > sample ? *srtt_ - sample : sample - *srtt_;
        rttvar_ = (3 * rttvar_ + err) / 4;
        srtt_ = (7 * *srtt_ + sample) / 8;
    }
    update_rto_from_estimates();
}

void TcpConnection::update_rto_from_estimates() {
    const Duration rto = *srtt_ + std::max<Duration>(std::chrono::milliseconds(1), 4 * rttvar_);
    rto_ = std::clamp(rto, kMinRto, kMaxRto);
}

// ===========================================================================
// Receiving
// ===========================================================================

std::uint32_t TcpConnection::receive_window() const noexcept {
    return recv_buffer_.size() >= kReceiveBufferSize
               ? 0
               : static_cast<std::uint32_t>(kReceiveBufferSize - recv_buffer_.size());
}

void TcpConnection::store_out_of_order(std::uint32_t seq, ByteView data) {
    if (out_of_order_bytes_ + data.size() > kReceiveBufferSize) return;
    for (const auto& [s, bytes] : out_of_order_) {
        if (s == seq && bytes.size() >= data.size()) return;  // duplicate
    }
    log::debug("tcp", "{} buffering out-of-order segment seq={} len={} (expected {})", tuple_, seq, data.size(),
               rcv_nxt_);
    out_of_order_.emplace_back(seq, Bytes(data.begin(), data.end()));
    out_of_order_bytes_ += data.size();
}

void TcpConnection::drain_out_of_order() {
    // Repeatedly pull in any buffered segment that now touches rcv_nxt.
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto it = out_of_order_.begin(); it != out_of_order_.end(); ++it) {
            const std::uint32_t start = it->first;
            const std::uint32_t end = start + static_cast<std::uint32_t>(it->second.size());
            if (seq_gt(start, rcv_nxt_)) continue;
            if (seq_gt(end, rcv_nxt_)) {
                const std::size_t skip = rcv_nxt_ - start;
                recv_buffer_.insert(recv_buffer_.end(), it->second.begin() + static_cast<std::ptrdiff_t>(skip),
                                    it->second.end());
                rcv_nxt_ = end;
            }
            out_of_order_bytes_ -= it->second.size();
            out_of_order_.erase(it);
            progress = true;
            break;
        }
    }
}

}  // namespace ustack
