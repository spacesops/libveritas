# @spacesops/react-native-libveritas

React Native bindings for [libveritas](https://github.com/spacesops/libveritas) — stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

This is a **prebuilt-binary** distribution: the Rust is compiled ahead of time and the resulting iOS `.xcframework` and Android shared libraries are shipped inside this npm package. **Consumers do not need a Rust toolchain** — `npm install` is enough.

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob) and [uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native).

## Installation

```bash
npm install @spacesops/react-native-libveritas
# or
yarn add @spacesops/react-native-libveritas
```

No Rust toolchain, `cargo-ndk`, or NDK is required on the consumer side — the native artifacts are already in the tarball.

For iOS, install pods:

```bash
cd ios && pod install
```

The CocoaPods podspec picks up the bundled `.xcframework` from the package, so no Rust compilation happens during `pod install`.

## Usage

### Verifying a message

```typescript
import {
  Veritas,
  Anchors,
  QueryContext,
  Message,
} from '@spacesops/react-native-libveritas';

// Load trust anchors
const anchors = Anchors.fromJson(anchorsJsonString);
const veritas = new Veritas(anchors);

console.log(`Anchors: ${veritas.oldestAnchor()} .. ${veritas.newestAnchor()}`);

// Build query context (empty = verify all handles)
const ctx = new QueryContext();
ctx.addRequest('alice@bitcoin');

// Verify a message (binary data from relay)
const msg = new Message(messageBytes);
const result = veritas.verifyMessage(ctx, msg);

// Inspect verified zones
for (const zone of result.zones()) {
  console.log(`${zone.handle()} -> ${zone.sovereignty()}`);

  // Store zone for later comparison
  const bytes = zone.toBytes();
}

// Compare zones
const better = newerZone.isBetterThan(olderZone);

// Get certificates
for (const cert of result.certificates()) {
  console.log(`${cert.subject} [${cert.certType}]`);
}
```

### Building a message

```typescript
import {
  MessageBuilder,
  RecordSet,
} from '@spacesops/react-native-libveritas';
import { createOffchainData } from '@spacesops/react-native-libveritas';

// Construct offchain data
const rs = new RecordSet(1, '{"nostr":"npub1...","ipv4":"127.0.0.1"}');
const sig = wallet.signSchnorr(rs.id());
const offchainBytes = createOffchainData(rs, sig);

// Build a message with certificates and offchain data
const builder = new MessageBuilder([
  { name: '@bitcoin', cert: rootCertBytes },
  { name: 'alice@bitcoin', offchainData: offchainBytes, cert: leafCertBytes },
]);

// Get the chain proof request to send to a provider
const request = builder.chainProofRequest();

// ... send request to provider, get chain proof back ...

const msg = builder.build(chainProofBytes);

// Serialize for transport
const bytes = msg.toBytes();
```

### Updating offchain data

```typescript
// Update offchain data on a verified message (no cert changes)
const msg = result.message();

const rs = new RecordSet(2, '{"nostr":"npub1new..."}');
const sig = wallet.signSchnorr(rs.id());
const offchainBytes = createOffchainData(rs, sig);

msg.update([
  { name: 'alice@bitcoin', offchainData: offchainBytes },
]);

const updatedBytes = msg.toBytes();
```

## Publishing (maintainers)

This package ships prebuilt native binaries inside the npm tarball so consumers never need to compile Rust. The build artifacts are git-ignored but included in the published package via the `files` array in `package.json` (which overrides `.gitignore` for `npm pack`/`npm publish`).

### Prerequisites (build machine only)

- [Rust](https://rustup.rs/) toolchain
- iOS targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`
- Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android`
- [cargo-ndk](https://github.com/nickel-org/cargo-ndk) (for Android): `cargo install cargo-ndk`
- Android NDK (via Android Studio or `sdkmanager`), with `ANDROID_NDK_HOME` set
- Xcode (for iOS)

### Build the binaries

From `bindings/react-native`:

```bash
yarn install
yarn build:binaries    # = ubrn:ios --release && ubrn:android --release
```

This produces:

- `SpacesopsReactNativeLibveritasFramework.xcframework` — iOS framework consumed by the generated podspec via `vendored_frameworks`
- `android/src/main/jniLibs/<abi>/*.a` — Android static libraries linked by CMake/Gradle (consumers need the NDK, which React Native Android builds require anyway, but **not** a Rust toolchain)
- `cpp/`, `ios/`, `android/`, `*.podspec`, `src/generated/` — generated turbo-module glue

> **Note on the `files` array:** ubrn 0.29.x names the iOS framework after the package
> (`SpacesopsReactNativeLibveritasFramework.xcframework`) and writes it at the package
> root. npm's `files` glob does not match this `.xcframework` *directory*, so it must be
> listed by its exact name in `package.json`'s `files` array (it already is). If you rename
> the package, regenerate with `yarn ubrn:ios` and update the `files` entry to match.

### Verify what gets published

Always check the tarball contents before publishing:

```bash
npm pack --dry-run
```

Confirm `SpacesopsReactNativeLibveritasFramework.xcframework/**`, `android/**/jniLibs/**`, `cpp/`, `ios/`, and `*.podspec` are listed.

> **Size warning:** the prebuilt static libraries (risc0/arkworks/secp256k1) are large.
> With all five ABIs (iOS arm64 + sim, Android arm64/armv7/x86_64) the tarball is ~150 MB,
> which is above npm's practical comfort zone (~120 MB) and close to the registry's
> ~200 MB `413 Payload Too Large` wall. If publish fails with `E413`, trim ABIs (e.g. drop
> Android `armeabi-v7a` and `x86_64`) in `ubrn.config.yaml` and rebuild.

### Publish

```bash
npm publish --access public
```

### Building from source (consumers who want to self-build)

The Rust source lives in this repo under `bindings/uniffi/`. Consumers who prefer to compile from source can clone the repo and run the same `yarn build:binaries` flow above; the `ubrn.config.yaml` points at `bindings/uniffi/Cargo.toml`.
