# NetGuardIDS - Project Updates & Bug Fixes

This file documents the critical bugs found during the project analysis and the fixes that were applied to make the project stable and ready for public release.

## 1. Feature Scale Mismatch (Time Units) - 🔴 CRITICAL (FIXED)
* **Issue:** `flow_state.py` calculated time-based features (`Flow Duration`, `IAT Mean/Max/Min`, `Active/Idle Mean`) in **Seconds**. However, the Machine Learning model was trained on the CICIDS-2017/2018 dataset, which measures all time-based features in **Microseconds**.
* **Fix:** Multiplied the time-difference variables in `flow_state.py` by `1,000,000` before passing them to the feature dictionary. This ensures that the Random Forest model receives correctly scaled inputs, drastically reducing False Positives.

## 2. Massive Memory Leak in Live Sniffer - 🔴 CRITICAL (FIXED)
* **Issue:** The `cleanup_stale_flows()` function in `live_ids_auto.py` was only being called when the script exited (inside the `finally` block). In a live environment, dropped or inactive connections stayed in the memory indefinitely, causing the RAM to fill up and the script to eventually crash.
* **Fix:** Integrated the `cleanup_stale_flows()` function into the `health_monitor` background thread so that stale flows are automatically cleared from the memory every 10 seconds.

## 3. Flow Fragmentation & Timeout Logic - 🟠 HIGH (FIXED)
* **Issue:** `live_ids_auto.py` forcibly removed flows from tracking and sent them for ML prediction after just 2 seconds (`FLOW_TIMEOUT`). For long connections (like video streams), this resulted in a single connection being fragmented into multiple 2-second flows with zeroed-out stats, corrupting features like `FIN Flag Cnt`.
* **Fix:** 
  1. Increased `FLOW_TIMEOUT` to 5 seconds.
  2. Added logic to check for `FIN` and `RST` TCP flags. Flows are now primarily evaluated when the connection naturally closes, matching how the ML model was trained on complete flows.

## 4. ARP Spoofing Network Bottleneck (DoS Risk) - 🟠 HIGH (FIXED)
* **Issue:** `ARP_SPOOF_ENABLED = True` was the default. On large/public networks, forcing all LAN traffic through a Python script using Scapy acts as a massive bottleneck, dropping packets and slowing down the entire network (effectively a Denial of Service).
* **Fix:** Set `ARP_SPOOF_ENABLED = False` by default. Added a warning for public users. Users can manually enable it for specific testing on home networks.

## 5. Flawed Training Data Sampling - 🟡 MODERATE (FIXED)
* **Issue:** `train_network_model.py` used blind random sampling (`df.sample()`) when reducing large CSV files. This risked completely discarding rare attack types present in the dataset.
* **Fix:** Implemented **Stratified Sampling** using a weight-based approach (`weights=1/weights`) in pandas. This ensures that minority attack classes are preserved proportionally during the down-sampling phase.

---
**Status:** All issues resolved. The project is now stable and safe for public release.
