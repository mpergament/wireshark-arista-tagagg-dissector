Based on https://eos.arista.com/analyzing-packet-header-timestamps-in-wireshark/

LIMITATIONS: Current assumption is that IP header follows TagAgg Arista header

**How to install on MAC OSX:**
1) Copy to /Applications/Wireshark.app/Contents/PlugIns/wireshark
2) Analyze -> Reload Lua Plugins in Wireshark

![](images/wireshark-decoded.jpg)