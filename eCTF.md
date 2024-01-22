# MITRE 2024 eCTF Challenge
<img src="https://ectfmitre.gitlab.io/ectf-website/_static/eCTF-RGB-color.png" alt="New MITRE eCTF Logo" width="250"/>

## Flag Submission Details (Remove after open-sourcing)
Username: ub@ectf.fake\
Password: 5bgrs3rCsCbSsrV6iKq4

## Competition links
* [Official eCTF Website](https://ectfmitre.gitlab.io/ectf-website/index.html)
* [Official eCTF Scoreboard](https://sb.ectf.mitre.org/)
* [Official eCTF Flag Submission Page](https://scoreboard.mitrecyberacademy.org/game)
* [Official eCTF Reference Design](https://github.com/mitre-cyber-academy/2024-ectf-insecure-example)
* [Official eCTF Schedule](https://ectfmitre.gitlab.io/ectf-website/2024/events/schedule.html)
* [Workshop Meeting Link](https://teams.microsoft.com/l/meetup-join/19%3ameeting_ZGRhZGM5OGEtYzgyNy00NDVkLWFhZDQtYWQ0M2NiN2NkNTVk%40thread.v2/0?context=%7b%22Tid%22%3a%22c620dc48-1d50-4952-8b39-df4d54d74d82%22%2c%22Oid%22%3a%226e533417-ddea-4a82-8fe9-faca9da9a7ae%22%7d)

<br>
<br>

## Analog Devices (MAX78000FTHR)
* [MAX78000FTHR Webpage](https://www.analog.com/en/design-center/evaluation-hardware-and-software/evaluation-boards-kits/max78000fthr.html#eb-overview)
* [MAX78000FTHR Datasheet](https://www.analog.com/media/en/technical-documentation/data-sheets/MAX78000FTHR.pdf)
* [MAX78000 Microcontroller Datasheet](https://www.analog.com/media/en/technical-documentation/data-sheets/max78000.pdf)
* [MAX78000FTHR Schematics](https://www.analog.com/media/en/technical-documentation/eval-board-schematic/max78000-fthr-schematic.pdf)
* [MAX78000FTHR User Guide](https://www.analog.com/media/en/technical-documentation/user-guides/max78000-user-guide.pdf)
* [Maxim Microcontrollers SDK (MSDK)](https://github.com/Analog-Devices-MSDK/msdk)
* [Maxim Microcontrollers SDK (MSDK) Documentation](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)
* [Custom OpenOCD Fork](https://github.com/analogdevicesinc/openocd)

<br>

**Overview**
* ARM Cortex-M4, RISC-V Core
* 512KB flash, 128KB SRAM, 16KB cache
* Neural network accelerator
* Camera, audio interface
* DAPLink debugger

<br>
<br>

## Nix Package Manager
* [Nix Documentation](https://nix.dev/)
* [Installing Nix](https://nixos.org/download#download-nix)
* [Nix Package Search](https://search.nixos.org/packages)
* [How Nix Works](https://nixos.org/guides/how-nix-works)

Nix is a system that can be utilized to create reproducible build systems. Nix will be used to build the MAX78000FTHR firmware instead of the previous years' Docker setup.

<br>
<br>

## Poetry - Python Packaging and Dependency Manager
* [Poetry Website](https://python-poetry.org)

Poetry is a Python packaging and dependency management utility. Poetry is utilized in the 2024 eCTF to manage dependencies for the eCTF tools, utilities, and additional build infrastructure. It should be automatically installed in your Nix environment.

<br>
<br>

## Other Links
### Tools
* [Draw.io (Diagramming)](https://drawio.com)

### Research Tools
* [Consensus](https://consensus.app)
* [Google Scholar](https://scholar.google.com)
* [Semantic Scholar](https://www.semanticscholar.org/)

### CactiLab
* [Github Repository](https://github.com/cactilab/2024-ectf-ub-cacti-design)

### Other
* [Brainstorm](brainstorm.md) -- A place for brainstorming
* [Nuggets](nuggets.md) -- A place to store bits of relevant knowledge
* [Reading List](reading_list.md) -- A list of relevant papers, articles, etc.


## Schedule
Todo.


## Tasks
Tasks will be primarily tracked using the [Github Issues](https://github.com/CactiLab/2024-ectf-ub-cacti-design/issues) page of this
repository. Using issues improves task accountability and visibility, and
allows better collaboration through the comments system.


## Team Members (Alphabetical)
* Dr. Hongxin Hu
* Dr. Ziming Zhao
* ASV Akhila
* MD Armanuzzaman
* Sai Bhargav M
* Alex Eastman (Team Leader)
* Kyle Lemma
* Gaoxiang Liu (Team Leader)
* Zheyuan Ma
* Sagar Mohan
* Rumaizi Mopuri
* Barani Rajendran
* Afton Spiegel
* Xi Tan


## Methodology Overview
For more detailed information, see the [Methodology](methodology.md) document.


## Results
For more detailed information, see the [Results](results.md) document.


## Codebase
Todo.

## Meeting Structure
Todo.


## Contributing
All contributions should be discussed with the team leaders before any effort
is put into them. This is to ensure that a contributor does not spend time on
a contribution only to have it rejected in the future.

All code contributions **must** be created on a separate branch and merged into
`main` with a pull request. Only the team leaders can review and approve pull
requests.

As a contributor, you will have access to everything in the repository. Please
take special care to leave things in the condition that you found them. I.e.,
do not arbitrarily change documents, `.gitignore` rules, folder / file structure,
etc. without first confirming the changes with the team leaders.

## Acknowledgements