# Anchor

Anchor is an Android application implementation for the upstream [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus/) project. It provides an on-device workflow through local ADB authentication and a separate Bootstrap action.

## Tested Kernels

| Device | Kernel | Status |
| --- | --- | --- |
| OnePlus 13 | `6.6.89-android15-8-g97a9aaefab9a-ab14519050-4k` | Successfully tested |
| OnePlus 13 | `6.6.30-android15-8-g013ec21bba94-abogki383916444-4k` | Successfully tested |
| OnePlus 13 | `6.6.118-android15-8-g93e223c276e7-abogki500782043-4k` | Successfully tested |

## Build

```powershell
.\gradlew.bat :app:assembleDebug
```


## Recommended Manager

Install [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU/actions) on the target device before running Anchor. KernelSU is also supported.

## Setup and Authorization

1. Enable Developer options and USB debugging on the device. For the initial TCP ADB setup, connect the device to an authorized computer and run:

   ```powershell
   adb tcpip 5555
   ```

2. Open Anchor. On a fresh installation, it automatically creates an ADB key pair in the app's private, non-backed-up storage. Importing computer keys is optional; existing imported keys are preserved.
3. Choose **Menu → Request ADB authorization**. Keep the phone unlocked and confirm the system dialog; select **Always allow** if you want subsequent connections to be remembered. An already trusted key connects without a dialog.
4. After authorization succeeds, disconnect USB and start Bootstrap when needed.

The authorization action only authenticates to local ADB. It does not execute a remote command or start Bootstrap. It waits up to two minutes and can be cancelled with **Stop**. Local TCP ADB must already be listening on port `5555`; this action cannot enable it without permission.

### Optional key import

Anchor normally uses its automatically generated local key pair. To reuse your own existing ADB identity, import both a matching `adbkey` and `adbkey.pub` through **Menu**. On Windows, computer keys are usually stored in `%USERPROFILE%\.android\`. Import only keys you control. Importing key files does not itself grant system authorization.

### TCP ADB configuration

Anchor connects to `127.0.0.1:5555`. The ADB daemon must listen on the same port. The standard setup command is `adb tcpip 5555`, run from an authorized computer.

For devices where TCP ADB is configured through system properties:

| Property | Purpose |
| --- | --- |
| `service.adb.tcp.port` | Runtime TCP ADB port; also used by the system authorization dialog on some Android versions. |
| `persist.adb.tcp.port` | Persistent TCP ADB port configuration, used when no runtime port is set. |

An administrator with an already authorized root ADB shell can configure the runtime port:

```powershell
adb shell setprop service.adb.tcp.port 5555
```

If TCP ADB should also be configured for subsequent boots, the persistent setting is optional:

```powershell
adb shell setprop persist.adb.tcp.port 5555
```

These commands require privileges; generating a key or requesting authorization does not provide them. Firmware may clear the runtime property after reboot, even when the persistent port remains set. Recheck the configuration after reboot rather than assuming both properties were restored.

### Troubleshooting

- **Authorization dialog disappears immediately without USB:** on some Android versions, the dialog watches USB connection state when the runtime TCP port is unset. A persistent port alone may leave this mismatch. Check that `service.adb.tcp.port` reflects the active TCP port; reconnecting USB can allow authorization while the configuration is corrected.
- **Connection refused:** confirm that USB debugging is enabled and local TCP ADB is listening on `5555`. The authorization action does not enable TCP ADB or change privileged system properties.
- **Authorization requested again:** Android can expire unused grants; the default timeout is seven days, but device settings may differ. Reauthorize the existing key instead of importing it again.
- **Only one key file is present:** import the matching missing file. Anchor preserves existing or partially imported keys instead of replacing them automatically.

The authorization action does not bypass Android consent. Computer-free operation requires TCP ADB to remain available; initial setup or setup after reboot may still require an authorized computer or administrator.

### Network access

TCP ADB is not limited to localhost just because Anchor connects to `127.0.0.1`. Legacy TCP ADB is unencrypted and may be reachable from the local network. Keep authentication enabled and use a trusted network; persistent configuration can keep the network debugging entry point available across boots.

## Release History

Version-specific changes and APK downloads are available on the [Releases page](https://github.com/byemaxx/ghostlock-anchor/releases).

## Disclaimer

For authorized security research and educational purposes only. You are responsible for ensuring you have permission to test any device and for understanding the potential impact before use. The authors and contributors accept no liability for data loss, device damage, or other consequences.
