# MITRE 2024 eCTF Challenge
<img src="https://ectfmitre.gitlab.io/ectf-website/_static/eCTF-RGB-color.png" alt="New MITRE eCTF Logo" width="250"/>

# eCTF Insecure Example
This repository holds the insecure example design for an eCTF MISC system.

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
* [Maxim Microcontrollers SDK (MSDK) Documentation (New Link)](https://analogdevicesinc.github.io/msdk//USERGUIDE/)
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

### Other
* [Brainstorm](brainstorm.md) -- A place for brainstorming
* [Nuggets](nuggets.md) -- A place to store bits of relevant knowledge
* [Reading List](reading_list.md) -- A list of relevant papers, articles, etc.

## Layout

- `application_processor` - Code for the application processor
    - `project.mk` - This file defines project specific variables included in the Makefile
    - `Makefile` - This makefile is invoked by the eCTF tools when creating a application processor
    - `inc` - Directory with c header files
    - `src` - Directory with c source files
    - `wolfssl` - Location to place wolfssl library for included Crypto Example
- `deployment` - Code for deployment secret generation
    - `Makefile` - This makefile is invoked by the eCTF tools when creating a deployment
    - You may put other scripts here to invoke from the Makefile
- `ectf_tools` - Host tools and build tools - DO NOT MODIFY ANYTHING IN THIS DIRECTORY
    - `attestation_tool.py` - Runs attestation command on application processor
    - `boot_tool.py` - Boots the application processor and sensors
    - `list_tool.py` - Lists what sensors are currently online
    - `replace_tool.py` - Replaces a sensor id on the application processor
    - `build tools` - Tools to build
- `component` - Code for the components
    - `project.mk` - This file defines project specific variables included in the Makefile
    - `Makefile` - This makefile is invoked by the eCTF tools when creating a component
    - `inc` - Directory with c header files
    - `src` - Directory with c source files
    - `wolfssl` - Location to place wolfssl library for included Crypto Example
- `shell.nix` - Nix configuration file for Nix environment
- `custom_nix_pkgs` - Custom derived nix packages
    - `analog-openocd.nix` - Custom nix package to build Analog Devices fork of OpenOCD


## Usage and Requirements

This repository contains two main elements: firmware source code and tooling.

Firmware is built through the included eCTF Tools. These tools invoke the Makefiles
in specific ways in the provided Nix environment. Firmware compiling should be executed 
through these included tools.

Source code and tooling is provided that runs directly on the host. All of these tools are 
created in Python. The tools can be easily installed with the use of Poetry. Once inside 
of the activated Nix environment, run `poetry install` to initialize the Poetry environment. 
These tools can be invoked either through `poetry run {toolname}` or by activating the poetry environment
with `poetry shell` and then running as standard python programs.

### Environment Build

The environment is built with a Nix, which should install all packages
necessary for running the design in a reproducible fashion. The environment is automatically 
built when an eCTF Build Tool is run. If building `analog_openocd.nix` this step may 
take some time to complete.

Development can be prototyped by launching into the Nix environment through `nix-shell`.

### Host Tools

Host Tools for the 2024 competition do not need to be modified by teams at any point. Your design
should work with the standardized interface between host and MISC system. The host tools will 
pass any required arguments to the MISC system and receive all relevant output.

### Deployment

When creating a deployment, the Makefile within the `deployment` folder of the design 
repo will be executed. This is the only stage in which information can be shared between 
separate portions of the build (e.g. components and application processors). A clean 
target should be implemented in this Makefile to allow for elimination of all generated secrets.

### Application Processor and Component

When building the application processor and components, the `Makefile` with the 
respective directories will be invoked. The eCTF Tools will populate parameters into 
a C header file `ectf_params.h` within the design directory. Examples of these header 
files can be found in the respective main source files for the application processor 
and component.

## Using the eCTF Tools
### Building the deployment 
This will run the `Makefile` found in the deployment folder using the following inputs:

```
ectf_build_depl --help
usage: eCTF Build Deployment Tool [-h] -d DESIGN

Build a deployment using Nix

options:
  -h, --help            show this help message and exit
  -d DESIGN, --design DESIGN
                        Path to the root directory of the included design
```

**Example Utilization**
```bash
ectf_build_depl -d ../ectf-2024-example
```
### Building the Application Processor
This will run the `Makefile` found in the application processor folder using the following inputs:

```
ectf_build_ap --help
usage: eCTF Build Application Processor Tool [-h] -d DESIGN -on OUTPUT_NAME [-od OUTPUT_DIR] -p P
                                             -b BOOT_MESSAGE

Build an Application Processor using Nix

options:
  -h, --help            show this help message and exit
  -d DESIGN, --design DESIGN
                        Path to the root directory of the included design
  -on OUTPUT_NAME, --output-name OUTPUT_NAME
                        Output prefix of the built application processor binary Example 'ap' -> a
  -od OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output name of the directory to store the result: default: .
  -p PIN, --pin PIN     PIN for built application processor
  -t TOKEN, --token TOKEN
                        Token for built application processor
  -c COMPONENT_CNT, --component-cnt COMPONENT_CNT
                        Number of components to provision Application Processor for
  -ids COMPONENT_IDS, --component-ids COMPONENT_IDS
                        Component IDs to provision the Application Processor for
  -b BOOT_MESSAGE, --boot-message BOOT_MESSAGE
                        Application Processor boot message
```

**Example Utilization**
```bash
ectf_build_ap -d ../ectf-2024-example -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build
```

### Building the Component
```
ectf_build_comp --help
usage: eCTF Build Application Processor Tool [-h] -d DESIGN -on OUTPUT_NAME [-od OUTPUT_DIR] -id COMPONENT_ID -b BOOT_MESSAGE -al
                                             ATTESTATION_LOCATION -ad ATTESTATION_DATE -ac ATTESTATION_CUSTOMER

Build an Application Processor using Nix

options:
  -h, --help            show this help message and exit
  -d DESIGN, --design DESIGN
                        Path to the root directory of the included design
  -on OUTPUT_NAME, --output-name OUTPUT_NAME
                        Output prefix of the built application processor binary Example 'ap' -> ap.bin, ap.elf, ap.img
  -od OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output name of the directory to store the result: default: .
  -id COMPONENT_ID, --component-id COMPONENT_ID
                        Component ID for the provisioned component
  -b BOOT_MESSAGE, --boot-message BOOT_MESSAGE
                        Component boot message
  -al ATTESTATION_LOCATION, --attestation-location ATTESTATION_LOCATION
                        Attestation data location field
  -ad ATTESTATION_DATE, --attestation-date ATTESTATION_DATE
                        Attestation data date field
  -ac ATTESTATION_CUSTOMER, --attestation-customer ATTESTATION_CUSTOMER
                        Attestation data customer field
```

**Example Utilization**
```bash
ectf_build_comp -d ../ectf-2024-example -on comp -od build -id 0x11111125 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"
```

## Flashing
Flashing the MAX78000 is done through the eCTF Bootloader. You will need to initially flash the eCTF Bootloader onto the provided hardware. 
This can be done easily by dragging and dropping the provided bootloader image to the DAPLink interface. DAPLink will show up as an external drive when connected to your system.

```
ectf_update [-h] --infile INFILE --port PORT

optional arguments:
  -h, --help       show this help message and exit
  --infile INFILE  Path to the input binary
  --port PORT      Serial port
```

**Example Utilization**
```bash
ectf_update --infile example_fw/build/firmware.img --port /dev/ttyUSB0
```

## Host Tools
### List Tool
The list tool applies the required list components functionality from the MISC system. This is availble on the 
PATH within the Poetry environment as `ectf_list`.

```
ectf_list -h
usage: eCTF List Host Tool [-h] -a APPLICATION_PROCESSOR

List the components connected to the medical device

options:
  -h, --help            show this help message and exit
  -a APPLICATION_PROCESSOR, --application-processor APPLICATION_PROCESSOR
                        Serial device of the AP
```

**Example Utilization**
``` bash
ectf_list -a /dev/ttyUSB0
```

### Boot Tool
The boot tool boots the full system. This is available on the PATH within the Poetry environment as `ectf_boot`

```
ectf_boot --help
usage: eCTF Boot Host Tool [-h] -a APPLICATION_PROCESSOR

Boot the medical device

options:
  -h, --help            show this help message and exit
  -a APPLICATION_PROCESSOR, --application-processor APPLICATION_PROCESSOR
                        Serial device of the AP
```

**Example Utilization**
``` bash
ectf_boot -a /dev/ttyUSB0
```

### Replace Tool
The replace tool replaces a provisioned component on the system with a new component.
This is available on the PATH within the Poetry environment as `ectf_replace`.

```
ectf_replace --help
usage: eCTF Replace Host Tool [-h] -a APPLICATION_PROCESSOR -t TOKEN -i COMPONENT_IN -o COMPONENT_OUT

Replace a component on the medical device

options:
  -h, --help            show this help message and exit
  -a APPLICATION_PROCESSOR, --application-processor APPLICATION_PROCESSOR
                        Serial device of the AP
  -t TOKEN, --token TOKEN
                        Replacement token for the AP
  -i COMPONENT_IN, --component-in COMPONENT_IN
                        Component ID of the new component
  -o COMPONENT_OUT, --component-out COMPONENT_OUT
                        Component ID of the component being replaced
```

**Example Utilization**
``` bash
ectf_replace -a /dev/ttyUSB0 -t 0123456789abcdef -i 0x11111126 -o 0x11111125
```

### Attestation Tool
The attestation tool returns the confidential attestation data provisioned on a component.
This is available on the PATH within the Poetry environment as `ectf_attestation`.

``` 
ectf_attestation --help
usage: eCTF Attestation Host Tool [-h] -a APPLICATION_PROCESSOR -p PIN -c COMPONENT

Return the attestation data from a component

options:
  -h, --help            show this help message and exit
  -a APPLICATION_PROCESSOR, --application-processor APPLICATION_PROCESSOR
                        Serial device of the AP
  -p PIN, --pin PIN     PIN for the AP
  -c COMPONENT, --component COMPONENT
                        Component ID of the target component
```

**Example Utilization**
```
ectf_attestation -a /dev/ttyUSB0 -p 123456 -c 0x11111124
```


## Schedule
Todo.
