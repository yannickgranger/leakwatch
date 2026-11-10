# LeakWatch

LeakWatch is an Android app that shows you which apps send data, where, and when.

It runs as a local VPN on the phone. Every connection goes through it and is recorded per app: destination address, DNS name, TLS server name (SNI), HTTP host, bytes in each direction, and whether the app was in front of you, in the background, or the screen was off. It flags connections to known trackers and suspicious traffic: data sent in the background or with the screen off, data from apps you have not opened today, large uploads, and cleartext data. It can also block domains, for one app or for all apps.

Nothing leaves the phone. LeakWatch relays traffic itself and writes its archive to the phone's storage.

LeakWatch is a proof of concept. It works, it is tested, but it is not a finished product.

## Limits

- Android runs one VPN at a time. Starting LeakWatch replaces any other VPN, WireGuard included, unless you build LeakWatch with its own embedded WireGuard (see **WireGuard (experimental)** below). After you stop watching, the app offers a button that opens the WireGuard app, if it is installed, so you can turn your tunnel back on.
- QUIC (UDP to port 443) is dropped on purpose. Apps then fall back to TCP and TLS, where the SNI is visible.
- DNS-over-HTTPS, certificate-pinned and hard-coded traffic is seen only by IP address and SNI. LeakWatch does not decrypt TLS.
- Minimum Android version: 10 (API 29).

## Build

You need a JDK 17 or newer and the Android SDK.

```
./gradlew :app:assembleDebug
```

With the embedded WireGuard built in:

```
./gradlew -Pleakwatch.wireguard=true :app:assembleDebug
```

Unit tests:

```
./gradlew :app:testDebugUnitTest
```

The test `WireGuardPeerIT` runs the embedded WireGuard against a real WireGuard peer in a Podman container. It is skipped unless you ask for it:

```
./gradlew -Dwg.it=1 :app:testDebugUnitTest --tests '*WireGuardPeerIT'
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

## Install and grants

```
adb install app/build/outputs/apk/debug/app-debug.apk
```

LeakWatch needs two grants:

- **VPN consent.** Android asks for it the first time you tap *Start watching*. To grant it without the dialog, for example on a test phone:

  ```
  adb shell appops set io.github.yannickgranger.leakwatch ACTIVATE_VPN allow
  ```

- **Usage access** (`GET_USAGE_STATS`), so LeakWatch can tell traffic from the app you are using apart from apps sending data on their own. The app opens the settings page for it, or:

  ```
  adb shell appops set io.github.yannickgranger.leakwatch GET_USAGE_STATS allow
  ```

To watch all night, let LeakWatch run without battery limits and turn on Always-on VPN for it. The app offers both.

## Remote commands

LeakWatch accepts commands through an intent extra `cmd`. The extra `pattern` holds a domain pattern, and the optional extra `package` holds an app package name. Without `package`, a rule applies to all apps.

```
adb shell am start -n io.github.yannickgranger.leakwatch/.MainActivity --es cmd start
adb shell am start -n io.github.yannickgranger.leakwatch/.MainActivity --es cmd stop
adb shell am start -n io.github.yannickgranger.leakwatch/.MainActivity --es cmd block_domain --es pattern '*.doubleclick.net'
adb shell am start -n io.github.yannickgranger.leakwatch/.MainActivity --es cmd block_domain --es pattern 'graph.facebook.com' --es package com.example.app
adb shell am start -n io.github.yannickgranger.leakwatch/.MainActivity --es cmd remove_rule --es pattern '*.doubleclick.net'
adb shell am start -n io.github.yannickgranger.leakwatch/.MainActivity --es cmd remove_rule --es pattern 'graph.facebook.com' --es package com.example.app
```

## Domain rules

A blocked name gets an NXDOMAIN answer from LeakWatch's DNS. A connection that reaches a blocked name anyway, by its TLS SNI or its HTTP `Host`, is reset.

Pattern syntax, case-insensitive, trailing dot ignored:

- `example.com` matches exactly that name.
- `*.example.com` matches `example.com` and every subdomain, such as `a.example.com` and `a.b.example.com`.
- `*` inside one label matches any characters within that label only, for example `ads*.example.com` matches `ads1.example.com` but not `ads.x.example.com`.

A rule either blocks or allows, and applies to one app (by package name) or to all apps. LeakWatch ships 18 default block rules for all apps; *Restore defaults* puts them back.

Precedence, exactly as `DomainPolicy` decides it, among the rules that match the name and apply to the app:

1. No rule matches: the name is allowed.
2. An allow rule for this app: allowed.
3. Otherwise, a block rule for this app: blocked.
4. Otherwise, an allow rule for all apps: allowed.
5. Otherwise (a block rule for all apps): blocked.

So a rule for one app always wins over a rule for all apps, and at the same level allow wins over block.

## Archive

LeakWatch writes one folder per day under:

```
/sdcard/Android/data/io.github.yannickgranger.leakwatch/files/archive/
```

Copy it to your computer:

```
adb pull /sdcard/Android/data/io.github.yannickgranger.leakwatch/files/archive ./archive
```

The *Export* button shares the same archive as a zip.

Layout:

- `YYYY-MM-DD/flows.jsonl`: one JSON object per connection.
- `YYYY-MM-DD/dns.jsonl`: one JSON object per DNS lookup: `ts`, `uid`, `label`, `name`, `qtype`, `answers`, `blocked`.
- `YYYY-MM-DD/dumps/`: the first bytes of cleartext connections, one text file per flow, named after the flow `id`.
- `YYYY-MM-DD/apps.csv`: the day per app: connections, bytes, destinations, tracker and suspicious connections, reasons, top destinations, blocked attempts.
- `offenders.csv`: at the archive root, apps ranked over the last 7 days by suspicious traffic, with screen-off and background bytes, tracker connections, reasons, top destinations and blocked attempts.

Keys in `flows.jsonl`:

- `id`: unique id of the connection.
- `ts_start`: when the connection opened, ISO 8601 with offset.
- `ts_end`: when it closed.
- `uid`: Android user id of the app.
- `packages`: package names that share this uid.
- `label`: the app's display name.
- `proto`: `tcp` or `udp`.
- `ip_version`: 4 or 6.
- `src`: source address and port on the phone.
- `dst`: destination address and port.
- `dns_name`: the name the app looked up for this address, if any.
- `sni`: the TLS server name from the ClientHello, if any.
- `http_host`: the HTTP `Host` header for cleartext HTTP, if any.
- `tracker`: true when the destination matches the tracker list.
- `bytes_out`: bytes sent by the app.
- `bytes_in`: bytes received by the app.
- `packets_out`: packets sent by the app.
- `packets_in`: packets received by the app.
- `blocked`: true when the app was blocked and the connection cut.
- `close_reason`: how the connection ended: `fin`, `rst_client`, `rst_upstream`, `connect_failed`, `idle`, `closed`, `capture_stopped`, `quic_dropped`, `blocked` or `domain_blocked`.
- `dump`: path of the cleartext dump under the day folder, or null.
- `app_state`: `foreground`, `background`, `screen_off` or `unknown` when the connection opened.
- `last_used`: when the app was last in the foreground, if known.
- `reasons`: why the connection is suspicious, see below.
- `suspicious`: true when `reasons` is not empty.
- `via`: `direct`, or `wireguard` when the connection went through the embedded WireGuard tunnel.

## Reasons

- `tracker`: the destination matches the tracker list.
- `telemetry_name`: the host name contains a telemetry-like word.
- `screen_off`: the app sent at least 1 KiB while the screen was off.
- `background`: the app sent at least 1 KiB while it was in the background.
- `not_used_today`: the app has not been opened today (system apps excluded).
- `cleartext_data`: the app sent data without encryption.
- `bulk_upload`: the app sent at least 50 KiB, more than it received.

Connections through the embedded WireGuard tunnel and connections cut by a domain rule carry no reasons.

## Report tool

`tools/leakwatch-report.py` reads a pulled archive and prints a summary: offenders, tracker domains, cleartext dumps with personal-data hints (email, device identifiers, location, phone numbers), and blocked attempts. It needs only Python 3.

```
python3 tools/leakwatch-report.py ./archive
```

## WireGuard (experimental)

Because Android runs one VPN at a time, LeakWatch can carry one WireGuard tunnel itself, so you keep your tunnel while you watch. This embedded WireGuard is a from-scratch, pure-Kotlin implementation of the WireGuard protocol (X25519, BLAKE2s, ChaCha20-Poly1305, the Noise IK handshake). It has not been audited. Do not rely on it for anything that matters.

It is off by default. A default build contains the code but never builds a tunnel, never reads a stored config, shows no WireGuard screen, and records every connection with `via` set to `direct`. To turn it on, build with:

```
./gradlew -Pleakwatch.wireguard=true :app:assembleDebug
```

In that build, the *WireGuard link* screen imports a config from a standard WireGuard export: a `.conf` file or the zip the WireGuard app exports, shared to LeakWatch or picked from storage. The config is stored encrypted with an AES key kept in the Android Keystore. Traffic to the tunnel's allowed addresses goes through the tunnel; everything else goes direct. A config that routes all traffic (`0.0.0.0/0` or `::/0`) is refused.

## License

MIT, see `LICENSE`.
