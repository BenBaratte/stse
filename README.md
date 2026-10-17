# stse

Zephyr module for [STSELib](https://github.com/STMicroelectronics/STSELib) (STSAFE-A secure
elements), with a Zephyr platform layer in `STSELib_Platform/`.

## Usage

- `CONFIG_STSELIB=y` builds STSELib and the platform layer.
- The application provides `stse_conf.h` and `stse_platform_generic.h` in an include path
  (`zephyr_include_directories`), and a devicetree alias `i2c-0` for the STSAFE I2C bus.
- Platform crypto services use PSA Crypto (hash, ECC key pairs, ECDH, ECDSA, HKDF). The
  required `PSA_WANT_*` options are listed in the help of `CONFIG_STSELIB`.
- Optional: `CONFIG_STSELIB_SHELL` (shell commands) and
  `CONFIG_MBEDTLS_STSELIB_TLS_CREDENTIAL` (TLS credential glue, needs a patched Zephyr).
- Log level: `CONFIG_STSELIB_LOG_LEVEL_*`.

Tested on NUCLEO-H563ZI with an STSAFE-A120 (X-NUCLEO-ESE01A1), Zephyr 4.5.0-rc1:
device info, certificate, ECDSA signature, host key establishment (ECDH + HKDF).
