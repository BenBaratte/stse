zephyr_sources_ifdef(CONFIG_STSELIB
STSELib/services/stsafea/stsafea_sessions.c
STSELib/services/stsafea/stsafea_echo.c
STSELib/services/stsafea/stsafea_ecc.c
STSELib/services/stsafea/stsafea_entity_auth.c
STSELib/services/stsafea/stsafea_reset.c
STSELib/services/stsafea/stsafea_patch.c
STSELib/services/stsafea/stsafea_mac.c
STSELib/services/stsafea/stsafea_symmetric_key_slots.c
STSELib/services/stsafea/stsafea_host_key_slot.c
STSELib/services/stsafea/stsafea_asymmetric_key_slots.c
STSELib/services/stsafea/stsafea_aes.c
STSELib/services/stsafea/stsafea_commands.c
STSELib/services/stsafea/stsafea_timings.c
STSELib/services/stsafea/stsafea_data_partition.c
STSELib/services/stsafea/stsafea_random.c
STSELib/services/stsafea/stsafea_password.c
STSELib/services/stsafea/stsafea_hash.c
STSELib/services/stsafea/stsafea_put_query.c
STSELib/services/stsafea/stsafea_wrap_unwrap.c
STSELib/services/stsafea/stsafea_low_power.c
STSELib/services/stsafea/stsafea_public_key_slots.c
STSELib/services/stsafea/stsafea_frame_transfer.c
STSELib/core/stse_frame.c
STSELib/core/stse_session.c
STSELib/core/stse_platform.c
STSELib/core/stse_generic_typedef.c
STSELib/core/stse_device.c
STSELib/certificate/stse_certificate_crypto.c
STSELib/certificate/stse_certificate.c
STSELib/certificate/stse_certificate_subparsing.c
STSELib/certificate/stse_certificate_prints.c
STSELib/api/stse_hash.c
STSELib/api/stse_device_authentication.c
STSELib/api/stse_aes.c
STSELib/api/stse_asymmetric_keys_management.c
STSELib/api/stse_symmetric_keys_management.c
STSELib/api/stse_data_storage.c
STSELib/api/stse_mac.c
STSELib/api/stse_device_management.c
STSELib/api/stse_random.c
STSELib/api/stse_ecc.c 
STSELib_Platform/stse_platform_i2c.c
STSELib_Platform/stse_platform_crypto.c
STSELib_Platform/stse_platform_aes.c
STSELib_Platform/stse_platform_power.c
STSELib_Platform/stse_platform_delay.c
STSELib_Platform/stse_platform_crc.c
STSELib_Platform/stse_platform_random.c
STSELib_Shell/stselib_shell.c
STSELib_Shell/stselib_mbedtls.c
crc16/crc16.c   )

zephyr_include_directories_ifdef(CONFIG_STSELIB STSELib/)
zephyr_include_directories_ifdef(CONFIG_STSELIB_SHELL STSELib_Shell/)


