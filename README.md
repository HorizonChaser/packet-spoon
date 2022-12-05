# packet-spoon

Packet capture tool based on Pcap and Qt

## Building

### Dependency

- CMake 3.10+
- QT 6.1+
- GCC (Clang not tested)
- Npcap installed

### Steps

First, add `QT_DIR` and `Qt6_Dir` to your environment variables if they are not set. They should point to `MinGW` folder inside Qt, perhaps like `C:\Qt\6.4.1\mingw_64`.

Then, use CMake in `.\build\`

```powershell
cmake .
make
```

Build outputs will be placed in `.\build\`.

## Planned Features

- [ ] GUI support
- [x] Detect all network interfaces
- [x] Packet capture on requested NIC
- [x] Parse packets and print out layered results
  - [x] Custom parser support
  - [ ] Plugin system
- [x] Dump result to *.pcap file
- [ ] Load existing \*.pcap file for analysis
