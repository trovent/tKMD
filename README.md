# tKMD + tKMDc
trovent Kernel-Mode Driver\
+\
trovent Kernel-Mode Driver communicator

# Usage: 
- Load driver\
![Loading Driver](./_readme.d/01_load_driver.png)
- Start driver communicator\
![Starting Driver Communicator](./_readme.d/02_driver_communicator_help.png)
- Remove PS_PROTECTION from LSASS process\
![Removing PS_PROTECTION](./_readme.d/06_remove_ps_protection_from_lsass.png)
- Locate callbacks\
![Locating Callbacks](./_readme.d/03_locate_callbacks.png)
- Remove process, thread and image callbacks\
![Removing Callbacks](./_readme.d/04_disable_callbacks.png)
- Verify\
![Verifying](./_readme.d/05_verify_callbacks_removed.png)

# Offsets
are already provided for the following builds:
- 10.0.26100
- 10.0.22621
- 10.0.22631
