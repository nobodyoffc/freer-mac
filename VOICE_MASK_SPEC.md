# Voice mask — cross-client spec

A FID's voice in calls and voice messages is not its owner's voice. Each FID
speaks with one synthetic voice, derived from the FID alone, so whoever holds
the FID sounds the same, and no one sounds like themselves. This is the voice
counterpart of the FID avatar (`FC-JDK/.../feature/avatar/AvatarMaker.java`).

Both clients implement this document. The same file is kept in both
repositories — `FreerForMac/VOICE_MASK_SPEC.md` and
`Freer/docs/VOICE_MASK_SPEC.md` — so change both together. It builds on
VOICE_SPEC (calls) and on the `VOICE` content type (FIMP0V2).

Status: **stopped, 2026-10-05, after Phase A** (§15, item 7). The spike
showed the design works for privacy but found no model small and fast enough
for a phone (Appendix A). Nothing is implemented. Instead, both clients tell users that calls and voice messages
carry their real voice (VOICE_SPEC §10). This document is kept as the design
to resume from.

## What this adds, and what it does not

**The goal:** a speaker-recognition system cannot link a FID's audio to
recordings of the person speaking behind it — even an attacker who has the
app, the model, the FID and recordings of the suspect (§1).

**In scope:**

- 1:1 calls and meetings (VOICE_SPEC).
- Voice messages (`VOICE`, FIMP0V2).
- Android (`Freer`) and Mac (`FreerForMac`).
- A mark that tells receivers the sender's voice is masked.

**Not in scope:**

- Hiding *what* is said, or accent, speaking rate and word choice (§8).
- Proving who is speaking. The voice proves nothing (§7).
- Choosing a voice, re-rolling it, or choosing its gender or age.
- Changing audio received from others.
- Other platforms. The FC-JDK CLI has no audio.

## Decisions

1. **One FID, one voice.** The voice is a function of the FID string and
   the mask version, and of nothing else: no salt, no user choice, no
   re-roll. Gender and age are not controlled; they fall where the hash
   puts them.
2. **Security comes from discarding, not from secrets.** The model, the
   basis and the derivation are all public, and the FID is public, so
   nothing about the target voice is secret. The protection is that the
   converter passes speech through a bottleneck that keeps the words and
   drops the speaker. Pitch, formant or EQ transforms (DSP), at any
   setting, are not a voice mask: their few parameters can be recomputed
   from the FID and inverted, and speaker recognition still links their
   output. No client offers DSP as a privacy option.
3. **Only on the sender's device.** Raw voice never leaves the device and
   is never stored (§9). Receivers do nothing to audio.
4. **On by default.** *Mask my voice* in Settings turns it off for every
   call and message (§11).
5. **Fail closed; warn per call.** If the voice cannot be masked, the
   client sends silence and asks. Consent to use the real voice covers one
   call, or one voice message, and never carries over (§10).
6. **Receivers show a mark.** The sender tells receivers its mask state in
   a way only the sender can produce (§5.3, §6.2). The mark is the
   sender's own claim: it protects the sender, and tells the receiver
   nothing about who is speaking.
7. **No change to the relay and no new wire format for calls.** The mask
   runs before Opus. The mark rides in a CONTROL media frame that already
   exists in VOICE_SPEC §5. Voice messages add one metadata field.
8. **The model is bundled and pinned.** It ships inside the app and is
   checked against a fixed SHA-256 before use. It is never downloaded: a
   swapped model could pass the real voice through and still claim to
   mask it.

## 1. Threat model

**The attacker** has:

- the app, so the model, the basis and this spec;
- audio from the target FID X: any call it took part in, or any voice
  message it received, since every receiver can record what it hears;
- reference recordings of a suspect P, such as public videos;
- an off-the-shelf speaker-recognition model (for example ECAPA-TDNN).

**The question it wants answered:** is P behind X?

| Attack | What the attacker does | Status |
|---|---|---|
| A1 (ignorant) | Compares X's audio with P's raw recordings. | Must fail (§2). |
| A2 (semi-informed) | Runs P's recordings through this converter with X's target voice, then compares with X's audio. This is the realistic attack, because everything it needs is public. | **The gate** (§2). |
| A3 (informed) | Trains a speaker-recognition model on converted speech (many speakers, many targets) to pick up what the converter leaks. | Measured and reported; a weaker bar (§2). |

**Out of reach of any converter:** what is said, accent and dialect, the
style of speech, network metadata (VOICE_SPEC §12), and the device itself.
§8 lists these for users.

## 2. Pass criteria

The gate for choosing a converter (Phase A, §14) and for every later
change to it. All figures are measured on speakers the model never trained
on.

| Measure | Pass |
|---|---|
| A2: equal error rate of the speaker-recognition attack, with ECAPA-TDNN | **≥ 40 %** (50 % is chance) |
| A1: equal error rate | ≥ 45 % |
| A3: equal error rate of a model trained on converted speech | ≥ 30 % (reported; below it needs a decision) |
| Intelligibility: Whisper word error rate | at most 5 points (absolute) above the raw recordings |
| Naturalness: predicted MOS (UTMOS) | ≥ 3.5 |
| **One voice:** for 100 FIDs, each spoken by ≥ 10 different source speakers, a speaker verifier set at its raw-speech equal-error threshold | accepts ≥ 90 % of same-FID pairs, rejects ≥ 90 % of different-FID pairs |
| No real person: outputs of 10 000 random FIDs that the verifier matches to any training speaker | < 1 % |
| Speed, Android (Galaxy A05s) | real-time factor ≤ 0.5 on CPU; algorithmic latency ≤ 60 ms; ≤ 150 MB memory; model ≤ 60 MB |
| Speed, Mac (M1) | real-time factor ≤ 0.2 |

The "one voice" row is what makes the FID, not the speaker, decide the
voice. The "no real person" row keeps a FID from landing on the voice of
someone in the training data.

## 3. The voice of a FID

```
seed = SHA-256( "FreerVoiceMask-v1" ‖ UTF-8(fid) )
for i in 0 .. 15:
    x   = first 8 bytes of SHA-256( seed ‖ u32be(i) ), as an unsigned big-endian 64-bit integer
    u   = ( (x >>> 11) + 0.5 ) / 2^53            // in (0, 1), never 0 or 1
    z_i = clamp( Φ⁻¹(u), -2.5, 2.5 )             // Φ⁻¹: inverse standard normal CDF
emb = μ + Σ_{i<16} σ_i · z_i · U_i
```

- `fid` is the FID that signs the call or message: the main FID in a call
  (VOICE_SPEC requires `liveFid == mainFid`), the sending FID for a voice
  message. A sub-FID that sends a voice message has its own voice.
- **The basis** (`μ`, `σ[16]`, `U[16]`) is a principal-component basis of
  the speaker embeddings of the model's training speakers. It ships with
  the model as `voicemask-v1.basis` and is part of the pinned version
  (§4.4). Its dimension is that of the chosen model's speaker embedding.
- **The clamp** keeps every voice inside the region where real voices
  lie, so none sounds strange. The bound is a Phase A parameter; 2.5 is
  the starting value.
- **Accuracy:** any `Φ⁻¹` accurate to 1e-12 will do. Shared vectors
  (`tools/vector-gen`) give `z` for a set of FIDs and are compared at 1e-9.
  `emb` itself need not match bit for bit across platforms: only the
  sender renders the voice, and a difference in the last bits is inaudible.
- **The version.** `FreerVoiceMask-v1` names the derivation, the model and
  the basis together. A new model is a new version and changes every
  FID's voice at once. A client ships exactly one version.

## 4. The converter

### 4.1. Pipeline

```
mic → platform voice processing, or AEC3 (VOICE_SPEC §9.2)
    → resample to the converter's rate
    → content encoder  → discrete speech units   (the bottleneck)
    → pitch: normalised, re-mapped to the target  (§4.2)
    → energy: normalised
    → synthesizer, conditioned on emb
    → resample → Opus (call) or AAC (voice message)
```

- **The bottleneck** is what removes the speaker. Phase A chooses it;
  discrete units (quantized self-supervised features) are the starting
  point, because continuous features keep measurable speaker information.
  Whatever is chosen must pass §2.
- **No enrollment.** The converter never sees a profile of the user's
  voice, never adapts to it, and stores nothing about it.
- **Streaming.** It works in chunks of 20 ms with at most 40 ms of
  lookahead, so calls and voice messages use the same model.

### 4.2. Pitch

The pitch contour is personal, and passing it through as it is would fail
A2. So:

- The source's log-F0 is normalised by its running mean and spread over
  voiced frames: a window of at least 3 s, started from population values.
- It is then rescaled to the target's mean and spread, which the model
  predicts from `emb`.
- If Phase A shows that even the normalised contour fails the gate, v1
  drops the source contour and lets the synthesizer predict pitch from the
  units alone.

### 4.3. Candidates

Phase A starts from published models with a license that allows shipping
(MIT, Apache-2.0, BSD or CC-BY weights; not non-commercial), including
StreamVC-style, OpenVoice tone-colour and LLVC-style designs. If none
passes §2 on the A05s, we train or distill our own on CC-BY data (LibriTTS,
VCTK). That choice is recorded in §15 when it is made.

### 4.4. Model files

| File | Android | Mac |
|---|---|---|
| Converter | `voicemask-v1.onnx`, ONNX Runtime Mobile (CPU, XNNPACK) | `VoiceMaskV1.mlpackage`, Core ML |
| Basis | `voicemask-v1.basis` | `voicemask-v1.basis` |

- Both converter files are built from the same weights.
- The client checks each file against its SHA-256, fixed in this section
  when Phase A passes, before loading it. A mismatch makes the mask
  *unavailable* (§10).

## 5. Calls

### 5.1. Where it runs

The mask runs after VOICE_SPEC §9.2 processing and before the Opus
encoder. Everything downstream is unchanged:

- Opus settings (VOICE_SPEC §9.1), frames, keys, attestations and the relay.
- The `level` byte and the VAD flag come from the converted signal.
- Echo cancellation runs before the mask on the raw near-end voice, and its
  far-end reference is the received audio, as now.

### 5.2. Delay

The mask adds its algorithmic latency (≤ 60 ms, §2) plus compute time.
VOICE_SPEC §9.4's target, "our stack adds ≤ 100 ms", is amended with
measured figures after Phase B.

### 5.3. The mark: a `VoiceState` CONTROL frame

A sender states its mask state in a media frame with `flags` = CONTROL
(`0x80`, VOICE_SPEC §5), whose payload is:

```
VoiceState {
  type     (1) = 0x56 ('V')
  version  (1) = 1
  state    (1) 0 = real voice, 1 = masked (FreerVoiceMask-v1)
}
```

It is sealed under the sender key and covered by the sender's attestations
like any other frame, so neither the relay nor another member can forge it.

**Sender:**

- Sends a `VoiceState` as its first frame after each join and after each
  path switch, on every change of state, and every 5 s.
- Gives it a `seq` of its own, as every CONTROL frame has (VOICE_SPEC
  §5.1), and the `timestamp` of the next audio frame, so it takes no audio
  time.

**Receiver:**

- MUST NOT pass a CONTROL payload to the Opus decoder, and MUST NOT treat
  a CONTROL frame's `seq` as a lost audio frame. **Check before Phase D:**
  Android's `CallMedia.open` today hands every opened payload to the
  jitter buffer, whatever its flags.
- Shows the mark for an `ssrc` while its latest `VoiceState`, by `seq`,
  says masked.
  - In a meeting, only once an attestation covering that frame has
    matched (VOICE_SPEC §5.1 step 3).
  - In a 1:1 call, at once (§5.1 step 5).
- Shows no mark before it has seen a `VoiceState`. No mark means "not
  masked, or not stated", never "masked".
- Ignores a `VoiceState` with a `version` it does not know.

## 6. Voice messages

### 6.1. Recording

Today both clients record straight to an AAC file: `MediaRecorder` on
Android, `AVAudioRecorder` on the Mac. That file is the raw voice on disk,
so recording changes:

1. Capture PCM in memory: `AudioRecord` (Android), an `AVAudioEngine`
   input tap (Mac).
2. Run each chunk through the converter as it arrives, so no more than one
   chunk of raw audio exists at a time.
3. Encode the converted PCM to AAC: `MediaCodec` + `MediaMuxer` (Android),
   `AVAudioFile` or `AVAudioConverter` (Mac).

The output format does not change: AAC, 16 kHz, 24 kbps (VoiceNote, 5 min
max). The encoded file may go to a temporary file, since it holds only the
masked voice. Playback before sending plays exactly what will be sent.

### 6.2. The mark

The `VOICE` metadata JSON gains one field:

```json
{"durationMs":1985,"sampleRate":16000,"format":"aac","voiceMask":"FreerVoiceMask-v1"}
```

- The field is present only when the audio was masked. Without it, the
  voice is real or not stated.
- It is inside the sealed, signed `body` (FIMP0V2), so it is the sender's
  own signed claim.
- Receivers that do not know it ignore it. Both clients' parsers already
  skip unknown fields (`VoiceNote.Meta`, `VoiceMessageHelper`); they gain a
  `voiceMask` reading for the mark.

## 7. The voice proves nothing

Anyone can make any FID's voice: the model and the derivation are public.
So:

- No screen may suggest that a voice confirms who is speaking. Who is
  speaking comes from the signatures (VOICE_SPEC §5.1, FIMP signatures),
  and the UI shows that.
- A modified client could speak in X's voice under another FID Y.
  Receivers see Y's name and identity; the voice is just a sound. Spotting
  that a voice belongs to another FID is not in v1.
- A modified client could send the real voice and still claim to be
  masked. That harms only its own user; the mark cannot protect a
  receiver, and does not try to.

A side effect: in Freer, a familiar voice is never evidence of anything,
which takes the power out of voice-cloning scams.

## 8. What still leaks

Users are told this plainly in *Mask my voice*'s explanation:

- **What you say**, and your accent, dialect, word choice and speaking
  rate. The converter keeps the words and much of their timing.
- **Laughs, coughs and other non-speech sounds**, which the converter may
  pass on in an altered but recognisable form.
- **Background sounds and the room**, reduced by noise suppression but not
  removed.
- **When you talk, and to whom** (VOICE_SPEC §12).
- **Your real voice**, whenever masking is off or you chose to use it for
  a call or message (§10).

## 9. Handling raw audio

Raw voice is the one thing this design must never let out. On both
clients:

- Raw PCM lives only in memory, in the capture → processing → converter
  path, and buffers are overwritten after use.
- It is never written to a file, a log, a crash report, analytics or a
  debug recording. Any existing debug audio dump (for example on the AEC3
  path) records the converted signal, or is compiled out of release
  builds.
- Nothing else taps the microphone ahead of the converter.
- On Android the call path runs in the `:voice` process (VOICE_SPEC §11.3),
  and the voice message path in the app process. Both follow these rules.

## 10. Failure and the per-call warning

**Availability.** At start, and once per app version per device, the client
checks:

- that the model files are present and match their hashes;
- that the converter runs fast enough: a benchmark on 3 s of bundled
  speech, against the §2 speed bar.

The result is *ok*, *too slow* or *unavailable*.

**Before a call** (placing, answering or joining), when *Mask my voice* is on
and the result is not *ok*:

> Freer can't mask your voice on this device. In this call others would
> hear your real voice.
>
> **[Use my real voice for this call]**  **[Cancel]** (default)

Answering keeps the call ringing while this is shown.

**During a call**, when the converter misses a frame's deadline:

- The sender sends nothing for that frame (DTX). It never sends any part
  of the raw signal, and never blends the two.
- After 1 s of misses within 3 s, it mutes the microphone and shows the
  same choice.
  - **Use my real voice:** unmasked for the rest of this call; a
    `VoiceState` 0 goes out at once.
  - **Stay muted** or **Hang up.**
  - If the converter catches up before the user chooses, it unmutes,
    still masked, and the prompt goes away.

**Voice messages:** the same check runs before recording starts, and the
choice is "Record with my real voice?" for that one message.

**Consent never carries over.** The next call or message is masked again,
and asks again if it has to.

## 11. What each client shows

- **Settings › Privacy:**
  - *Mask my voice*, on by default. Turning it off shows §8 and asks for
    confirmation. When off, calls send `VoiceState` 0 and messages carry
    no `voiceMask` field.
  - *Hear my voice:* records 5 s and plays it back in the FID's voice.
    Nothing is kept.
- **Own call screen:** "Your voice: masked" or "Your voice: real".
- **The mark, for others:** a mask icon beside the speaker's name on the
  call screen and in a meeting's participant list, and on voice message
  bubbles. Its tooltip: "This FID's app says the voice is masked. A voice
  never shows who is speaking."
- No mark is shown for others whose state is unknown or real.

## 12. Platform notes

- **Android:** ONNX Runtime Mobile works on minSdk 28. The CPU provider
  (XNNPACK) is the baseline; NNAPI is optional and only if it measures
  faster. The model loads on first use, in the `:voice` process for calls
  and in the app process for messages. The APK grows by the model's size
  (≤ 60 MB, §2).
- **Mac:** Core ML (the Neural Engine where present), in the `FCVoice`
  package. The tap is after `setVoiceProcessingEnabled(true)`. The model
  sits in the signed app bundle.

## 13. Protocol documents

Written once Phase A has frozen §3 and §4:

| Document | Change |
|---|---|
| `IM/FIMP5V1_Call.md` | The `VoiceState` CONTROL payload (§5.3), and the rule that CONTROL payloads never reach the decoder. |
| `IM/FIMP0V2_FIMP.md` | The `voiceMask` field in `VOICE` metadata (§6.2). |
| A new voice mask document | §2 (pass criteria), §3 (derivation), §4.4 (pinned files), §7 (what the mark means). Its name is chosen when it is written. |
| `VOICE_SPEC.md` §9.4 | The delay target, with Phase B's figures (§5.2). |

## 14. Implementation plan

Each phase ends at a **gate**. A phase does not start until the gate before
it has passed.

### Phase A — Model spike (desktop)

- A Python lab in `FreerForMac/tools/voicemask-lab`, never shipped (removed after the stop; its results are Appendix A).
- Evaluate the §4.3 candidates against every row of §2, with the A2 attack
  run exactly as §1 describes.
- Build the basis, settle the clamp and the pitch handling (§4.2).
- **Gate:** one converter passes §2 (the A05s speed row may be estimated
  here and is confirmed in Phase B). Output: the chosen model and its
  license, the basis, the `z` vectors for `tools/vector-gen`, and a
  written report of every §2 figure.
- If nothing passes, stop and decide whether to train our own (§4.3).

### Phase B — On device

- Convert the model to ONNX and Core ML; implement §3 and the hash check
  on both clients; run the streaming converter on files.
- **Gate:** §2's speed rows met on the A05s, the S22+ and an M1; the
  `z` vectors match on both clients; the on-device output passes A2 and
  "one voice" from a re-run of the Phase A report.

### Phase C — Voice messages

- §6 on both clients: in-memory capture, the converter, AAC encoding, the
  `voiceMask` field and the mark; §10 for messages; §11 settings.
- **Gate:** a message recorded on each client plays on the other with the
  same voice for the same FID; no raw audio file exists at any point
  (checked on the file system during recording); masking off, and the
  real-voice choice, behave as §10 says.

### Phase D — Calls

- §5 on both clients: the converter in the capture path, `VoiceState`, the
  receiver rules of §5.3, the mark, the per-call warning and the in-call
  fallback (§10).
- **Gate:** 1:1 calls and a meeting between Mac and Android with masking
  on; the mark shows correctly; forcing the converter to stall mutes and
  prompts, and never lets raw audio through; the measured delay is
  recorded for VOICE_SPEC §9.4.

### Phase E — Hardening

- Run A3 (§1) on device output and report it.
- Check §9 on both clients: no raw audio in files, logs or debug dumps.
- Write the protocol documents (§13).

## 15. Decisions record

Answered 2026-10-05, before Phase A:

1. **The attacker is a speaker-recognition system** that tries to link a
   FID's audio to recordings of the real speaker, with full knowledge of
   the system (§1). Fooling acquaintances alone is not the goal, which
   rules out DSP-only masks (Decision 2).
2. **Mac and Android.** No other platform in v1.
3. **Gender and age are ignored.** They come out of the hash like
   everything else (§3).
4. **On by default, and one FID has exactly one voice.** No re-roll and no
   choice of voice (Decision 1).
5. **When the voice cannot be masked, the user is warned for that call**
   and may go on with the real voice for that call only (§10). Calls are
   not blocked outright, because masking is on by default and that would
   rule out calls on slow phones.
6. **There is a global off switch, and receivers see a mark** (§5.3, §6.2,
   §11).

Answered 2026-10-05, after Phase A:

7. **Stopped.** Phase A failed its gate (Appendix A).
   - Privacy passed. A discrete-unit cascade (discrete Soft-VC → FreeVC)
     held the informed attacker to A2 45 % and A1 47 %, and 46 % / 51 %
     across recording sessions. It kept one voice per FID. Continuous
     features alone (FreeVC) let A2 fall to 20 %.
   - Word error rate was +6.0 points, just over the limit.
   - The stack is 483 M parameters, an estimated RTF of 5–8 on the A05s,
     and not streaming.
   - Training a compact streaming model of our own was the alternative,
     and it was declined. Both clients show a real-voice notice instead
     (VOICE_SPEC §10).

## Appendix A. Phase A report (2026-10-05)

Measured against VOICE_MASK_SPEC §2 with a Python harness (removed after the stop). The attacker
throughout is SpeechBrain ECAPA-TDNN (VoxCeleb), cosine scoring. Data:
LibriSpeech test-clean (40 speakers, or 28 for cross-chapter) to evaluate;
dev-clean + dev-other (73 other speakers) for the basis. Each speaker speaks
as one lab FID.

### A.1. Results

Same-chapter (strict: trial and attacker reference share a recording session):

| Converter | A2 | A1 | One voice (same accept / diff reject) | WER raw → conv | UTMOS | Params |
|---|---|---|---|---|---|---|
| no conversion | 0 % | 0 % | — | — | — | — |
| FreeVC (continuous WavLM) | **20 %** | 36 % | 93 / 96 | 2.5 → 4.5 | 4.01 | 355 M |
| Soft-VC, discrete units (one voice for all) | 43 % | 48 % | fails by design | 2.5 → 7.2 | 4.14 | 128 M |
| **Discrete Soft-VC → FreeVC** | **45 %** | **47 %** | 99.8 / 91.4 | 2.5 → 8.5 | 4.08 | 483 M |

Quick runs (12 speakers only, noisy): soft-unit Soft-VC A2 37 %; discrete
Soft-VC → OpenVoice v2 A2 43 %, A1 34 %, one voice 96 / 82.

Cross-chapter (realistic: different sessions), discrete Soft-VC → FreeVC,
28 speakers: **A2 46 %, A1 51 %**, one-voice EER 2.4 %.

Speed, 2 CPU threads on an M2 Pro, 6.6 s utterance:

| Stage | RTF | Params |
|---|---|---|
| HuBERT-base (discrete units) | 0.015 | 94.7 M |
| Soft-VC acoustic model | 0.105 | 18.9 M |
| HiFi-GAN | 0.084 | 14.4 M |
| WavLM-Large | 0.053 | 315.5 M |
| FreeVC synthesizer | 0.077 | 39.3 M |
| **Total** | **0.334** | **482.8 M** |

The M2 does matrix products on its AMX unit, so these RTFs flatter the
transformers. By operation count the cascade is about 70–80 GFLOP per second of
audio; a Galaxy A05s's two Cortex-A75 cores sustain roughly 10–15 GFLOP/s, so
an estimated **RTF 5–8 on the A05s** against the 0.5 required. The weights are
~1.9 GB in fp32 (~0.5 GB int8) against 60 MB. Every stage is also
non-streaming (full-utterance attention).

### A.2. Findings

1. **The principle works.** A discrete-unit bottleneck removes the speaker
   well enough to pass both attacks: A2 45–46 %, A1 47–51 %. Continuous
   features do not: FreeVC alone lets the informed attacker link speakers
   80 % of the time (A2 20 %). Decision 2 of the spec is confirmed.
2. **One voice per FID works** with a FreeVC-style speaker-conditioned
   second stage and the §3 derivation (16 PCA components, clamp 2.5).
3. **Intelligibility narrowly fails**: +6.0 WER points against ≤ +5, mostly
   from the 100-cluster discrete units (+4.6 alone).
4. **Nothing off the shelf can ship.** The passing stack is ~8× too big
   and ~10–15× too slow for the A05s, and it is not streaming.

### A.3. Caveats

- English read speech only. The unit model (HuBERT-base, LibriSpeech) is
  English; Mandarin or other languages would need multilingual units and
  were not measured.
- One attacker model (ECAPA). A3 (an attacker trained on converted speech)
  was not run.
- "No real person" (§2) was not measured: the training speakers of the
  models (VCTK, LJSpeech) are not in the lab.
- 40 speakers; the EERs have a margin of a few points.

### A.4. Gate

**Not passed.** Privacy and voice-identity rows pass. WER narrowly fails.
Speed and size fail by an order of magnitude. Per §14, Phase A stops here
for the decision in §4.3: train our own compact streaming model, or stop.
