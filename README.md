# LegacyGPSFix

A modern GPS restoration, rollover fix, and navigation enhancement tweak for legacy iOS devices (**iOS 6.0 – 6.1.6**).

---

## Features

- **GPS Week Number Rollover Fix (+1024 weeks):**  
  Corrects date and timestamp calculations on legacy Qualcomm and Broadcom basebands affected by the April 2019 GPS rollover.
- **Autonomous & On-Demand A-GPS Assistance:**  
  Embeds pre-cached Qualcomm XTRA assistance data with automatic direct HTTP fallback mirrors, bypassing modern TLS certificate expiry issues on legacy iOS.
- **Precision Navigation Filters:**  
  - *SiRF-style Static Navigation:* Eliminates erratic location jumping and jitter while stationary.
  - *Kinematic Velocity Gate:* Rejects unrealistic multipath spikes and teleportation jumps.
  - *Low-Lag Alpha Smoothing:* Produces clean, fluid location tracks.
- **Location Override (Fake GPS):**  
  Built-in static location spoofer (defaults to Apple HQ Cupertino), ideal for testing and navigation apps on Wi-Fi-only hardware without a cellular baseband.
- **Position Calibration:**  
  Fine-tune local antenna and indoor offsets in meters directly from Settings.
- **Privacy-Friendly & Lightweight:**  
  Runs quietly in the background within `locationd` and target apps without battery drain or intrusive alerts.

---

## Compatibility

- **iOS Versions:** iOS 6.0 – 6.1.6
- **Architecture:** ARMv7 (32-bit)
- **Devices:** iPhone 3GS, iPhone 4, iPhone 4S, iPhone 5, iPad 2, iPad 3, iPad 4, iPad mini 1, iPod touch 4th/5th gen.

---

## Repository & Installation

Add the official Cydia repository:
```text
https://noname122021.github.io/cydia-repo/
```
Search for **LegacyGPSFix** in Cydia and install. Settings are available under **Settings $\to$ LegacyGPSFix**.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
