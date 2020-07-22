[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/DeimosC2/DeimosC2/blob/master/LICENSE)

# DeimosC2
Deimos is in: __Beta__

DeimosC2 is a post-exploitation Command & Control (C2) tool that leverages multiple communication methods in order to control machines that have been compromised. DeimosC2 server and agents works on, and has been tested on, Windows, Darwin, and Linux. It is entirely written in [Golang](https://golang.org/) with a front end written in [Vue.js](https://vuejs.org/).

### Listener Features
* Each listener has it's own RSA Pub and Private key that is leveraged to wrap encrypted agent communications.
* Dynamically generate agents on the fly
* Graphical map of listener and agents that are tied to it

### Agent Features
* Agent list page to give high level overview
* Agent interaction page containing info of agent, ability to run jobs against agent, filebrowser, loot data, and ability to add comments

### Supported Agents
* TCP
* HTTPS
* DoH (DNS over HTTPS)
* QUIC
* Pivot over TCP

### Frontend Features
* Multi-User support with roles of admin and user
* Graphs and visual interaction with listeners and agents
* Password length requirements
* 2FA Authentication using Google MFA
* Websocket API Calls

## Getting Started and Help
You can download the latest [release](https://github.com/DeimosC2/DeimosC2/releases) and view the [release](https://github.com/DeimosC2/DeimosC2/wiki) for any assistance getting started or running the C2.

## Submitting Issues
We welcome issues to be opened to help improve this project and keep it going. For bugs please use the [template](.github/ISSUE_TEMPLATE/bug_report.md).

## Authors
* Chase Dardaman ([@CharlesDardaman](https://twitter.com/CharlesDardaman))
* Quentin Rhoads-Herrera ([@paragonsec](https://twitter.com/paragonsec))
* Elvira Sheina ([developeruz](https://github.com/developeruz))
* Blase Brignac ([@BlaiseBrignac](https://twitter.com/BlaiseBrignac))

## Credits
In order to develop this we used some of the awesome work of others. Below is a list of those we either used their code or were inspired by. If we missed you please let us know so we can add your name!
* [lsassy](https://github.com/Hackndo/lsassy) by [@hackndo](https://twitter.com/HackAndDo) used for some Windows modules
* [goDoH](https://github.com/sensepost/goDoH) by [@leonjza](https://twitter.com/leonjza) from SensePost used for DoH
* [BishopFox Sliver](https://github.com/BishopFox/sliver) used in some places as they already did a fanstastic job
* [Merlin](https://github.com/Ne0nd0g/merlin) used for reflective DLLs support
* [dgoogauth](https://github.com/dgryski/dgoogauth) used for the 2FA functionality
* [gobfuscate](https://github.com/unixpickle/gobfuscate) used to support agent obfuscation
* [Stack Overflow](https://stackoverflow.com/) because isn't this how we develop now?