# dupfinder

A simple commandline utility for finding duplicate files by comparing file attributes and file data, whilst also offering an option to merge duplicate files into a single, common file through use of hardlinks.



### Building

dupfinder can be built for Windows and Unix, and consists of a singular source file (`main.c`)

Windows:

- Open `dupfinder.sln` in Visual Studio and hit *build*

Linux:

- ```sh
  gcc -o dupfinder main.c
  ```
- For portability, the following options can be defined if you get build errors by default:
	- `-DNO_STRUCT_STAT_ST_TIM`: `struct timespec stat::st_{amc}tim` doesn't exist
	- `-DHAVE_STRUCT_STAT_ST_TIMESPEC`: `struct timespec stat::st_{amc}timespec` exists
	- `-DHAVE_STRUCT_STAT_ST_TIMENSEC`: `<unsigned ?> stat::st_{amc}timensec` exists
	- `-DNO_STRUCT_DIRENT_D_TYPE`: `unsigned char dirent::d_type` doesn't exist



### Usage

To prevent accidental use, `dupfinder` operates in a sort-of *dry-run* mode by default. In this mode, it will scan directories and files, before printing the groups of identical files it wants to link to each other like this:

```sh
$ dupfinder /usr/include
dupfinder: info: scanning: '.'...
dupfinder: info: scanning: 'yajl/'...
dupfinder: info: scanning: 'xorg/'...
dupfinder: info: scanning: 'xcb/'...
[...]
group:["cygwin/icmp.h","icmp.h"]
group:["w32api/txctx.h","w32api/mtsgrp.h","w32api/mtsevents.h"]
group:["w32api/scardsrv.h","w32api/sspsidl.h","w32api/scardmgr.h","w32api/scarddat.h"]
group:["python3.5m/pgen.h","python2.7/pgen.h","python3.7m/pgen.h","python3.6m/pgen.h"]
group:["python3.7m/enumobject.h","python3.6m/enumobject.h","python3.5m/enumobject.h","python2.7/enumobject.h"]
group:["python2.7/metagrammar.h","python3.5m/metagrammar.h","python3.7m/metagrammar.h","python3.6m/metagrammar.h"]
group:["python3.6m/bltinmodule.h","python3.5m/bltinmodule.h","python3.7m/bltinmodule.h"]
[...]
group:["gpgrt.h","gpg-error.h"]

saved_disk_inode: 91
total_disk_inode: 4714
saved_disk_space: 272.23KiB
total_disk_space: 83.30MiB
```

To automatically merge these *group*s into the same inode, you must run `dupfinder -P /usr/include` (the `-P` mirroring `ln(1)`'s `-P` argument that is also used to create hardlinks).

Additionally, the `saved_disk_inode: NNN` tells you how many INodes can/were freed via file merging, and `saved_disk_space: NNN` tells you how much file space can/was freed.

