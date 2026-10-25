# Anchor

Anchor is an Android application implementation for the upstream [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus/) project. It provides a local USB-debugging workflow of ghostlock.

## Tested Kernel

| Device | Kernel | Status |
| --- | --- | --- |
| OnePlus 13 | `6.6.89-android15-8-g97a9aaefab9a-ab14519050-4k` | Successfully tested |
| OnePlus 13 | `6.6.30-android15-8-g013ec21bba94-abogki383916444-4k` | Successfully tested |
| OnePlus 13 | `6.6.118-android15-8-g93e223c276e7-abogki500782043-4k` | Successfully tested |

## Build

```powershell
.\gradlew.bat :app:assembleDebug
```


## recommended

Install [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU/actions) on the target device before running Anchor.(KernelSU is also supported)

## First Use

1. Enable Developer options and USB debugging on the device. For the initial TCP ADB setup, connect the device to an authorized computer and run:

   ```powershell
   adb tcpip 5555
   ```

2. Open Anchor. On a fresh installation, it automatically creates an ADB key pair in the app's private, non-backed-up storage. Importing computer keys is optional; existing imported keys are preserved.
3. Choose **Menu → Request ADB authorization**. Keep the phone unlocked and confirm the system dialog; select **Always allow** if you want subsequent connections to be remembered. An already trusted key connects without a dialog.
4. After authorization succeeds, disconnect USB and start Bootstrap when needed.

The authorization action only authenticates to local ADB. It does not execute a remote command or start Bootstrap. It waits up to two minutes and can be cancelled with **Stop**. Local TCP ADB must already be listening on port `5555`; this action cannot enable it without permission.

### Authorization troubleshooting

If the authorization dialog flashes and disappears without USB connected, verify the TCP ADB setup. On the tested device, `persist.adb.tcp.port=5555` with an empty `service.adb.tcp.port` caused the system dialog to dismiss immediately; synchronizing the runtime port to `5555` allowed authorization without USB. Running `adb tcpip 5555` from an authorized computer is the standard setup step. A privileged administrator can inspect and correct the runtime property when necessary.

The runtime property may reset after reboot. Anchor does not automatically modify privileged system properties, bypass authorization, or guarantee computer-free setup after every reboot. Android may also expire unused ADB grants after seven days; the key files themselves do not expire.

TCP ADB is not limited to localhost just because Anchor connects to `127.0.0.1`. Legacy TCP ADB is unencrypted and may be reachable from the local network; keep authentication enabled and use a trusted network. Import only key pairs you control, if you choose the optional import workflow.

## v1.6

- Add **Request ADB authorization**, using the existing app-local key generation so fresh installations no longer require importing computer keys.
- Keep authorization separate from Bootstrap, with visible progress, a two-minute wait and cancellation.
- Document the TCP ADB prerequisite, USB-dependent dialog dismissal, and reboot limitations.

## Disclaimer

For authorized security research and educational purposes only. You are responsible for ensuring you have permission to test any device and for understanding the potential impact before use. The authors and contributors accept no liability for data loss, device damage, or other consequences.
