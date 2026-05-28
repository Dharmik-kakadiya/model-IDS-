import time
import numpy as np
from scapy.layers.inet import IP, TCP, UDP  # use proper layer classes, not strings


class FlowState:

    def __init__(self, key, first_packet):
        self.key = key
        self.start_time = time.time()
        self.last_seen = self.start_time

        self.dst_port = key[3]
        self.protocol = key[4]

        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        self.totlen_fwd_pkts = 0
        self.totlen_bwd_pkts = 0

        self.fwd_pkt_lengths = []
        self.bwd_pkt_lengths = []
        self.all_pkt_lengths = []

        self.timestamps = []
        self.fwd_timestamps = []
        self.bwd_timestamps = []

        self.active_times = []
        self.idle_times = []
        self.prev_time = None

        # Header
        self.fwd_header_len = 0
        self.bwd_header_len = 0

        # Window
        self.init_fwd_win_bytes = 0
        self.init_bwd_win_bytes = 0

        self.fwd_act_data_pkts = 0

        # Flags  (RFC 793 + RFC 3168)
        # Bit positions: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08,
        #                ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.psh_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.urg_flag_cnt = 0
        self.ece_flag_cnt = 0   # ECE = 0x40
        self.cwr_flag_cnt = 0   # CWR = 0x80  (was "cwe" — typo fixed)

        # Direction-specific PSH/URG flag counts (needed by model)
        self.fwd_psh_flag_cnt = 0
        self.bwd_psh_flag_cnt = 0
        self.fwd_urg_flag_cnt = 0
        self.bwd_urg_flag_cnt = 0

        # BUG FIX: fwd_ip must be initialised to None before update() is called.
        # Previously it was only set inside update() when tot_fwd_pkts==0, but if
        # the first packet had no IP layer update() returned early, leaving fwd_ip
        # undefined and causing AttributeError on the next packet.
        self.fwd_ip = None

        # Behaviour features
        self.unique_dst_ports = set()
        self.total_packets = 0
        self.total_bytes = 0

        self.update(first_packet)

    def update(self, packet):

        now = time.time()

        if self.prev_time is not None:
            gap = now - self.prev_time
            if gap > 1:
                self.idle_times.append(gap)
            else:
                self.active_times.append(gap)

        self.prev_time = now
        self.last_seen = now

        pkt_len = len(packet)

        self.total_packets += 1
        self.total_bytes += pkt_len

        self.all_pkt_lengths.append(pkt_len)
        self.timestamps.append(now)

        # BUG FIX: use Scapy layer class (IP), not string "IP".
        # `"IP" not in packet` checks the string in packet fields (wrong);
        # `IP not in packet`  checks for the IP layer   (correct).
        if IP not in packet:
            return

        src_ip = packet[IP].src

        # BUG FIX: fwd_ip initialised in __init__ so this is always safe.
        if self.fwd_ip is None:
            self.fwd_ip = src_ip

        is_forward = (src_ip == self.fwd_ip)

        if is_forward:
            self.tot_fwd_pkts += 1
            self.totlen_fwd_pkts += pkt_len
            self.fwd_pkt_lengths.append(pkt_len)
            self.fwd_timestamps.append(now)
        else:
            self.tot_bwd_pkts += 1
            self.totlen_bwd_pkts += pkt_len
            self.bwd_pkt_lengths.append(pkt_len)
            self.bwd_timestamps.append(now)

        if TCP in packet:

            tcp = packet[TCP]

            self.unique_dst_ports.add(tcp.dport)

            # BUG FIX: tcp.dataofs can be None for truncated/malformed packets
            # causing TypeError: unsupported operand type(s) for *: 'NoneType' and 'int'
            # Fix: fall back to standard 5 (20-byte TCP header) when None.
            header_len = (tcp.dataofs or 5) * 4

            if is_forward:
                self.fwd_header_len += header_len
                if self.tot_fwd_pkts == 1:
                    self.init_fwd_win_bytes = tcp.window
                if len(tcp.payload) > 0:
                    self.fwd_act_data_pkts += 1
            else:
                self.bwd_header_len += header_len
                if self.tot_bwd_pkts == 1:
                    self.init_bwd_win_bytes = tcp.window

            flags = int(tcp.flags)

            # BUG FIX: ECE=0x40, CWR=0x80 (corrected from "cwe" typo)
            if flags & 0x01: self.fin_flag_cnt += 1
            if flags & 0x02: self.syn_flag_cnt += 1
            if flags & 0x04: self.rst_flag_cnt += 1
            if flags & 0x08:
                self.psh_flag_cnt += 1
                if is_forward: self.fwd_psh_flag_cnt += 1
                else:          self.bwd_psh_flag_cnt += 1
            if flags & 0x10: self.ack_flag_cnt += 1
            if flags & 0x20:
                self.urg_flag_cnt += 1
                if is_forward: self.fwd_urg_flag_cnt += 1
                else:          self.bwd_urg_flag_cnt += 1
            if flags & 0x40: self.ece_flag_cnt += 1
            if flags & 0x80: self.cwr_flag_cnt += 1

        elif UDP in packet:

            udp = packet[UDP]
            self.unique_dst_ports.add(udp.dport)

    def flow_duration(self):
        return max(self.last_seen - self.start_time, 1e-6)

    def compute_stats(self, arr):
        if len(arr) == 0:
            return 0, 0, 0, 0
        return np.mean(arr), np.std(arr), np.max(arr), np.min(arr)

    def compute_iat_stats(self, timestamps):
        if len(timestamps) < 2:
            return 0, 0, 0, 0, 0
        iats = np.diff(timestamps)
        return np.mean(iats), np.std(iats), np.max(iats), np.min(iats), np.sum(iats)

    def build_basic_features(self):

        duration = self.flow_duration()

        def stats(arr):
            if len(arr) == 0:
                return 0, 0, 0, 0
            return np.max(arr), np.min(arr), np.mean(arr), np.std(arr)

        fwd_max, fwd_min, fwd_mean, fwd_std = stats(self.fwd_pkt_lengths)
        bwd_max, bwd_min, bwd_mean, bwd_std = stats(self.bwd_pkt_lengths)

        pkt_min  = float(np.min(self.all_pkt_lengths))  if self.all_pkt_lengths else 0
        pkt_max  = float(np.max(self.all_pkt_lengths))  if self.all_pkt_lengths else 0
        pkt_mean = float(np.mean(self.all_pkt_lengths)) if self.all_pkt_lengths else 0
        pkt_std  = float(np.std(self.all_pkt_lengths))  if self.all_pkt_lengths else 0
        pkt_var  = float(np.var(self.all_pkt_lengths))  if self.all_pkt_lengths else 0

        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min, _ = self.compute_iat_stats(self.timestamps)
        fwd_iat_mean,  fwd_iat_std,  fwd_iat_max,  fwd_iat_min,  fwd_iat_tot  = self.compute_iat_stats(self.fwd_timestamps)
        bwd_iat_mean,  bwd_iat_std,  bwd_iat_max,  bwd_iat_min,  bwd_iat_tot  = self.compute_iat_stats(self.bwd_timestamps)

        active_mean, active_std, active_max, active_min = self.compute_stats(self.active_times)
        idle_mean,   idle_std,   idle_max,   idle_min   = self.compute_stats(self.idle_times)

        down_up_ratio = self.tot_bwd_pkts / self.tot_fwd_pkts if self.tot_fwd_pkts > 0 else 0

        total_len = self.totlen_fwd_pkts + self.totlen_bwd_pkts
        total_pkts = self.tot_fwd_pkts + self.tot_bwd_pkts
        pkt_size_avg = total_len / total_pkts if total_pkts > 0 else 0

        features = {

            "Dst Port":      self.dst_port,
            "Protocol":      self.protocol,
            "Flow Duration": duration * 1e6,

            "Tot Fwd Pkts": self.tot_fwd_pkts,
            "Tot Bwd Pkts": self.tot_bwd_pkts,

            "TotLen Fwd Pkts": self.totlen_fwd_pkts,
            "TotLen Bwd Pkts": self.totlen_bwd_pkts,

            "Fwd Header Len": self.fwd_header_len,
            "Bwd Header Len": self.bwd_header_len,

            "Down/Up Ratio": down_up_ratio,

            # Direction-specific PSH/URG flag counts
            "Fwd PSH Flags": self.fwd_psh_flag_cnt,
            "Bwd PSH Flags": self.bwd_psh_flag_cnt,
            "Fwd URG Flags": self.fwd_urg_flag_cnt,
            "Bwd URG Flags": self.bwd_urg_flag_cnt,

            # Average packet size across all packets in flow
            "Pkt Size Avg": pkt_size_avg,

            # Bulk rate features — require L7 segmentation, set to 0
            # (model trained with these as 0 for most flows too)
            "Fwd Byts/b Avg":   0,
            "Fwd Pkts/b Avg":   0,
            "Fwd Blk Rate Avg": 0,
            "Bwd Byts/b Avg":   0,
            "Bwd Pkts/b Avg":   0,
            "Bwd Blk Rate Avg": 0,

            "Fwd Seg Size Avg": fwd_mean,
            "Bwd Seg Size Avg": bwd_mean,
            "Fwd Seg Size Min": fwd_min,

            "Init Fwd Win Byts": self.init_fwd_win_bytes,
            "Init Bwd Win Byts": self.init_bwd_win_bytes,

            "Fwd Act Data Pkts": self.fwd_act_data_pkts,

            "Fwd Pkt Len Max":  fwd_max,
            "Fwd Pkt Len Min":  fwd_min,
            "Fwd Pkt Len Mean": fwd_mean,
            "Fwd Pkt Len Std":  fwd_std,

            "Bwd Pkt Len Max":  bwd_max,
            "Bwd Pkt Len Min":  bwd_min,
            "Bwd Pkt Len Mean": bwd_mean,
            "Bwd Pkt Len Std":  bwd_std,

            "Pkt Len Min":  pkt_min,
            "Pkt Len Max":  pkt_max,
            "Pkt Len Mean": pkt_mean,
            "Pkt Len Std":  pkt_std,
            "Pkt Len Var":  pkt_var,

            "Flow Byts/s": (self.totlen_fwd_pkts + self.totlen_bwd_pkts) / duration,
            "Flow Pkts/s": (self.tot_fwd_pkts    + self.tot_bwd_pkts)    / duration,
            "Fwd Pkts/s":   self.tot_fwd_pkts / duration,
            "Bwd Pkts/s":   self.tot_bwd_pkts / duration,

            "Flow IAT Mean": flow_iat_mean * 1e6,
            "Flow IAT Std":  flow_iat_std  * 1e6,
            "Flow IAT Max":  flow_iat_max  * 1e6,
            "Flow IAT Min":  flow_iat_min  * 1e6,

            "Fwd IAT Tot":  fwd_iat_tot  * 1e6,
            "Fwd IAT Mean": fwd_iat_mean * 1e6,
            "Fwd IAT Std":  fwd_iat_std  * 1e6,
            "Fwd IAT Max":  fwd_iat_max  * 1e6,
            "Fwd IAT Min":  fwd_iat_min  * 1e6,

            "Bwd IAT Tot":  bwd_iat_tot  * 1e6,
            "Bwd IAT Mean": bwd_iat_mean * 1e6,
            "Bwd IAT Std":  bwd_iat_std  * 1e6,
            "Bwd IAT Max":  bwd_iat_max  * 1e6,
            "Bwd IAT Min":  bwd_iat_min  * 1e6,

            "FIN Flag Cnt":   self.fin_flag_cnt,
            "SYN Flag Cnt":   self.syn_flag_cnt,
            "RST Flag Cnt":   self.rst_flag_cnt,
            "PSH Flag Cnt":   self.psh_flag_cnt,
            "ACK Flag Cnt":   self.ack_flag_cnt,
            "URG Flag Cnt":   self.urg_flag_cnt,
            # BUG FIX: was "CWE Flag Count" (wrong name). CWR = Congestion Window Reduced.
            "CWE Flag Count": self.cwr_flag_cnt,   # keep key name for model compat
            "ECE Flag Cnt":   self.ece_flag_cnt,

            "Subflow Fwd Pkts": self.tot_fwd_pkts,
            "Subflow Fwd Byts": self.totlen_fwd_pkts,
            "Subflow Bwd Pkts": self.tot_bwd_pkts,
            "Subflow Bwd Byts": self.totlen_bwd_pkts,

            "Active Mean": active_mean * 1e6,
            "Active Std":  active_std  * 1e6,
            "Active Max":  active_max  * 1e6,
            "Active Min":  active_min  * 1e6,

            "Idle Mean": idle_mean * 1e6,
            "Idle Std":  idle_std  * 1e6,
            "Idle Max":  idle_max  * 1e6,
            "Idle Min":  idle_min  * 1e6,
        }

        return features