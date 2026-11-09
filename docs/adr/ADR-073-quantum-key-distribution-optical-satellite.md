# ADR-073: Quantum Key Distribution (QKD) Optical Fiber & Satellite Entanglement Key Exchange Protocol (BB84 / E91)

- **Status**: Accepted
- **Date**: 2026-11-09
- **Deciders**: Velcrux Cryptography, Optical Transport, Aerospace Engineering, and Security Operations Teams
- **Consulted**: Distributed Systems, Edge Infrastructure, and Quantum Communications Research Teams

---

## 1. Context and Problem Statement

As quantum computing architectures advance toward cryptanalytically relevant quantum computers (CRQC), asymmetric public-key cryptosystems (such as RSA, ECDHE, and DSA) become vulnerable to polynomial-time factorisation and discrete logarithm attacks via Shor's algorithm. While post-quantum cryptography (PQC, e.g., ML-KEM-768 and ML-DSA-65 implemented in Option CD) provides computational hardness against quantum attacks, its mathematical foundations remain unproven against unexpected algorithmic breakthroughs.

Furthermore, long-term archival data transfers and mission-critical government, banking, and data-center replication infrastructures demand **information-theoretic security (ITS)**—security governed strictly by the laws of quantum physics rather than computational assumptions.

To achieve this:
1. **Discrete-Variable Photon Loss & Eavesdropping Interception**: Photon transmission across terrestrial standard single-mode optical fiber (Corning SMF-28 at 1550 nm, $\alpha = 0.20\text{ dB/km}$) and Low Earth Orbit (LEO) satellite-to-ground downlinks undergoes severe geometric diffraction, atmospheric turbulence, and optical attenuation.
2. **Photon-Number-Splitting (PNS) Vulnerability**: Real-world weak coherent pulse (WCP) laser sources periodically emit multi-photon states, allowing an eavesdropper (Eve) to split off photons without detection unless rigorous multi-intensity decoy-state protocols are enforced.
3. **Bell Non-Locality & Device Independence**: Quantum entanglement protocols require empirical verification of Clauser-Horne-Shimony-Holt (CHSH) Bell inequality violations ($S > 2.0$) to guarantee that no local hidden variables or classical eavesdropping intercepts exist.
4. **Key Lifecycle & PQC Hybrid Binding**: Distributed key management systems require standards-compliant (ETSI GS QKD 014 / 004) key buffering, automated replenishment, and cryptographic defense-in-depth binding with post-quantum KEMs.

To address these imperatives, Velcrux requires an integrated **Quantum Key Distribution (QKD) Optical Fiber & Satellite Entanglement Key Exchange Protocol Engine** supporting BB84 and E91 protocols in 100% pure safe Rust.

---

## 2. Decision Drivers

- **BB84 Decoy-State Protocol Engine**:
  - Discrete-variable 4-quantum state encoding across rectilinear $\{|0\rangle, |1\rangle\}$ and diagonal $\{|+\rangle, |-\rangle\}$ polarization/phase bases.
  - 3-intensity decoy-state method ($\mu=0.50$ signal, $\nu=0.10$ decoy, $\omega=0.00$ vacuum) to foil photon-number-splitting (PNS) attacks and estimate lower-bound single-photon yield $Y_1$.
  - Quantum Bit Error Rate (QBER) estimation with asymptotic Shor-Preskill security abort threshold ($QBER < 11.0\%$).
  - Cascade parity bisection error reconciliation algorithm and Toeplitz matrix universal hash privacy amplification.
- **Ekert 1991 (E91) Entangled Bell State Protocol Engine**:
  - Maximally entangled Bell pair $|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$ generation and transmission.
  - Three-angle measurement basis configurations for Alice ($a_1=0^\circ, a_2=45^\circ, a_3=90^\circ$) and Bob ($b_1=22.5^\circ, b_2=45^\circ, b_3=67.5^\circ$).
  - Clauser-Horne-Shimony-Holt (CHSH) Bell inequality evaluation: $S = |E(a_1,b_1) - E(a_1,b_3) + E(a_3,b_3) - E(a_3,b_1)|$.
  - Security verification: Classical limit $S \le 2.0$ vs quantum Tsirelson bound $S \le 2\sqrt{2} \approx 2.8284$, aborting when $S \le 2.0$.
  - Sifted key extraction using matching polarization angles ($a_2 = b_2 = 45^\circ$).
- **Optical Fiber & Free-Space Satellite Channel Physics**:
  - Terrestrial optical fiber model: Beer-Lambert attenuation $\alpha = 0.20\text{ dB/km}$ at 1550 nm, group velocity $c/n \approx 204{,}757\text{ km/s}$, detector quantum efficiency $\eta \approx 85\%$, and dark count rate $\sim 10\text{ Hz}$.
  - LEO satellite downlink model: Geometric beam divergence $\theta = \frac{1.22 \lambda}{w_0}$, telescope aperture collection $A_{rx}$, atmospheric absorption ($0.5\text{ dB}$ at zenith), and slant range geometry $L = h / \cos(\zeta)$.
- **ETSI GS QKD 014 / 004 Key Buffer & Hybrid PQC Binding**:
  - Secure Application Entity (SAE) key management with UUID indexing and lifecycle states (`Available`, `Reserved`, `Consumed`, `Expired`).
  - Automated background buffer replenishment daemon maintaining target quantum key depth.
  - Dual-layer defense-in-depth hybrid key derivation binding QKD entropy with ML-KEM-768 shared secrets:
    $$K_{hybrid} = \text{BLAKE3-KDF}(K_{QKD} \mathbin{\Vert} K_{PQC} \mathbin{\Vert} \text{"velcrux-hybrid-qkd-pqc-v1"})$$
- **Zero Unsafe Code**: Strict `#![forbid(unsafe_code)]` compliance across all QKD modules.

---

## 3. Technical Architecture

```
                  +-------------------------------------------------------------+
                  |         ETSI GS QKD 014 / 004 KEY MANAGEMENT BUFFER         |
                  |  - Key IDs (UUIDs)     - Status: Available/Reserved/Consumed|
                  |  - 256-bit AES-GCM     - Automated Replenisher Daemon       |
                  +------------------------------+------------------------------+
                                                 |
                                     Key Injection / Fetch
                                                 |
                  +------------------------------v------------------------------+
                  |                QUANTUM PROTOCOL ENGINE                      |
                  |                                                             |
                  |  [BB84 Decoy-State Engine]     [E91 Entanglement Engine]     |
                  |  - 4 Quantum States            - Bell Pair |\Phi^+\rangle   |
                  |  - 3 Intensities (\mu, \nu, \omega) - CHSH Bell Test (S > 2)     |
                  |  - Cascade Error Correction    - Tsirelson Bound S <= 2\sqrt{2}|
                  |  - Toeplitz Hash Privacy Amp   - Matching Angle Sifting     |
                  +------------------------------+------------------------------+
                                                 |
                                     Optical Channel Simulation
                                                 |
                  +------------------------------v------------------------------+
                  |               QUANTUM OPTICAL CHANNEL PHYSICS               |
                  |                                                             |
                  |  [Terrestrial SMF-28 Fiber]   [LEO Satellite Downlink]      |
                  |  - \alpha = 0.20 dB/km (1550nm)- Slant Range L = h / cos(\zeta)|
                  |  - Delay \Delta t = L * n / c - Beam Divergence Loss        |
                  |  - SNSPD Detector \eta = 85%  - Atmospheric Attenuation     |
                  +-------------------------------------------------------------+
```

---

## 4. Security Considerations

1. **Information-Theoretic Security**: The security of BB84 and E91 keys relies on the no-cloning theorem and quantum non-locality. Any eavesdropping attempt perturbs quantum states, elevating QBER above the $11.0\%$ threshold or collapsing the CHSH $S$ parameter below $2.0$.
2. **Photon-Number-Splitting (PNS) Immunity**: The 3-intensity decoy-state technique precisely bounds Eve's information on multi-photon pulses by tracking transmission yields of signal ($\mu$), decoy ($\nu$), and vacuum ($\omega$) pulses.
3. **Hybrid Defense-in-Depth**: By combining QKD entropy with post-quantum ML-KEM-768 via BLAKE3 KDF, the system remains secure even if one layer were theoretically compromised or physically severed.

---

## 5. Consequences

### Positive
- Information-theoretically secure symmetric key establishment for long-term data archival and edge replication.
- Support for both terrestrial fiber networks and space-to-ground satellite downlinks.
- Standards-compliant integration via ETSI GS QKD 014 key buffers.
- Unified operator CLI suite (`velcrux qkd status`, `exchange`, `keys`, `replenish`).

### Negative
- Quantum channel key rate scales inversely with physical fiber distance due to exponential optical attenuation ($0.2\text{ dB/km}$).
