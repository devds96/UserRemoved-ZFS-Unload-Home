# Purpose
The code in this repo is intended to help with a common problem on
Ubuntu zfs installations with encrypted home directories: When the user
logs out, the home directory remains open and the encryption key remains
loaded.

While `pam_zfs_key` handles the login procedure just fine (unlocking the
home directory and mounting it), it sometimes may not be able to lock
the directory on logout because processes may still be accessing the
home directory. In the syslog, a message similar to this appears:
```log
Mar 25 04:40:40 ubuntu sshd[98055]: pam_zfs_key(sshd:session): zfs_unmount failed with: -1
```

Here, a solution is attempted by hooking into the User Removed D-Bus
event and locking the home directory if applicable. To achieve this, the 
session counter file managed by `pam_zfs_key` must be locked while 
unmounting and unloading the key file to prevent race conditions.


# Installation
To install, perform the following steps as root (`sudo -i`):

  0. Inspect the code of this repo.
  1. Copy the service file `user-removed-zfs-unload-home.service` into
    `/etc/systemd/system` (from the `systemd` directory).
  2. Copy the python file `user_removed_zfs_unload_home.py` into
    `/usr/local/bin` (from the `src` directory).
  3. `apt install python3-dbus-next`.
  4. Make the python file executable: 
    `chmod +x /usr/local/bin/user_removed_zfs_unload_home.py`
  5. Start and enable the service:
    `systemctl enable user-removed-zfs-unload-home` and
    `systemctl start user-removed-zfs-unload-home`.


# Known issues
  1. It takes around 10-15s for the D-Bus "user removed" signal to
  arrive at the script. In this time, logging in as a different user
  could make it possibe for this user to re-mount the home directory.
  However, there might not be a way to migitate this except with an
  ealier event that triggers after all processes of the user have
  necessarily stopped.
