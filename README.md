Based on https://eos.arista.com/analyzing-packet-header-timestamps-in-wireshark/

It will decode following 2 types of packets following Arista TapAgg Header:
1) L3 IP
2) L2 header

**How to install on MAC OSX:**
1) Copy to /Applications/Wireshark.app/Contents/PlugIns/wireshark
2) Analyze -> Reload Lua Plugins in Wireshark

![](images/wireshark-decoded.jpg)