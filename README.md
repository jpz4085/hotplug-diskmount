# hotplug-diskmount
OpenBSD removable disk automounter for use with hotplugd and toad.

The hotplug-diskmount utility can be started by hotplugd(8) from an attach script for the disk drive
(2) device class, or by toad(8) and terminates when device is detached.  It mounts all supported
partitions the disk contains.  hotplug-diskmount polls attached devices for media insertion or removal
every 2 seconds.  It is useful to detect and mount correctly disks inserted into card-readers and CD/DVD drives.

By default all mount points are created in the /media directory, which should have been created beforehand
by the init command. The default directory can be changed with the -d option.

Changes
-------
- Added support for exfat-fuse in addition to ntfs3g
- Changed default mount directory to /media for GUnixMount support
- Extended mount routine to use partition volume label for mount point

Links
-----
Original author: Alexey Vatchenko http://www.bsdua.org/hotplug-diskmount.html
