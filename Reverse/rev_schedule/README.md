# Reverse Engineering Challenge: rev_schedule (CBC)

## Challenge Details
* **Category:** Reverse Engineering
* **Difficulty:** Medium / Hard
* **Flag:** `TDCTF{sh0uld_i_bl0ck_g1thub_b3c4us3_1t_1s_u5ed_by_m4lw4re?}`

---

## Challenge Summary
This challenge simulates a threat actor using an Excel Macro (`.xlsm`) to fetch and decrypt a payload string hosted on a public GitHub Issue Comment. 

The reverse engineering path for participants:
1. Extract and analyze the VBA Macros inside `Latest CBC Schedule.xlsm`.
2. Identify the target GitHub repository (`s3cr3t_b4db10c`) and API endpoint `/issues/comments`.
3. Fetch the target comment containing `hostname`, `os`, `username`, and `ciphertext`.
4. Reverse the multi-layered encoding/encryption scheme:
   * Custom Base64 table lookup (`KdauhQCHrjc9GyWAYgoU72x8kzVRlZ3BSN14vsieIptX6JTDPmEq5FOL0nMwfb+/`).
   * Byte-by-byte XOR using `CustomCrc32` (Polynomial `0xdeadb33f`) keyed on `username`, byte offset, and `repo_name`.
   * ChaCha20 decryption using `nonce = md5(hostname)[:12]` and a 32-byte key derived from a seed (timestamp from GitHub comment `created_at`).
   * Seed bruteforce using Rust `rand::rngs::StdRng` (implemented in pure Python inside `solver.py`).

---

## Files Included

| File | Description |
| :--- | :--- |
| `generate_challenge.py` | Generator script to encrypt any flag and output GitHub comment payload body. |
| `solver.py` | Standalone Python solver with built-in Rust `StdRng` (`ChaCha12Rng` + `PCG32`) implementation. |
| `README.md` | Challenge author documentation and deployment steps. |

---

## How to Deploy the Challenge

### Step 1: Generate Payload
Run `generate_challenge.py` to create the encrypted payload text:
```bash
python generate_challenge.py
```
*Output Comment Body:*
```text
hostname: MALWARE-PC, os: Windows 10 Pro, username: victim_user, ciphertext: zR+oPNCJfkDOf8DhHfqdx/kU1rGeMTNLFRW4k75enlS0FkzrQDATeoNynIyilryczx5EaUrxPv3iuWh=
```

### Step 2: Post to GitHub
Post the generated comment body to an Issue Comment in your target public GitHub repository (e.g., `github_username/s3cr3t_b4db10c`).

### Step 3: Verify with Solver
Run `solver.py` to verify that the flag is recovered correctly:
```bash
python solver.py
```

### Step 4: Share Workbook
Distribute `Latest CBC Schedule.xlsm` (or `rev_schedule.zip`) to CTF participants.
