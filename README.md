# Anchor

Anchor is an Android application implementation for the upstream [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus/) project. It provides a local USB-debugging workflow of ghostlock.

## Tested Kernel

| Device | Kernel | Status |
| --- | --- | --- |
| OnePlus 13 | `6.6.89-android15-8-g97a9aaefab9a-ab14519050-4k` | Successfully tested |

## Build

```powershell
.\gradlew.bat :app:assembleDebug
```


## recommended

Install [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU/actions) on the target device before running Anchor.

## First Use

1. Enable Developer options and USB debugging on the device, then connect it to your computer.
2. On the computer, enable local ADB-over-TCP:

   ```powershell
   adb tcpip 5555
   ```

3. In Anchor, open **Menu** and import a matching `adbkey` and `adbkey.pub` pair. On Windows, these are usually located in `%USERPROFILE%\.android\`.
4. Confirm the ADB authorization prompt on the device when it appears, then start Bootstrap.

Import only a key pair you control. The private key is required for the local ADB authentication step.

## Disclaimer

For authorized security research and educational purposes only. You are responsible for ensuring you have permission to test any device and for understanding the potential impact before use. The authors and contributors accept no liability for data loss, device damage, or other consequences.
