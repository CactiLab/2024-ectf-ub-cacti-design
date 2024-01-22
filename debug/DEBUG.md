## Debug with OpenOCD and Cortex-Debug

Install the Cortex-Debug extension for VSCode.

To configure Visual Studio Code with the Cortex-Debug extension and OpenOCD, you will need to create a launch configuration in Visual Studio Code that tells the extension information about your debug session such as the source code location, the path to your OpenOCD executable, and the board configuration files for OpenOCD to use.

Set the `cortex-debug.armToolchainPath` setting in VSCode to the path to your ARM GNU Toolchain installation in Nix. This will allow the extension to find the arm-none-eabi-gdb executable.

Set the `cortex-debug.openocdPath` setting in VSCode to the path to the custom fork of OpenOCD binary by Analog Devices in Nix. This will allow the extension to find the openocd executable.

To find the above path, run `which arm-none-eabi-gdb` and `which openocd` in the nix-shell. The example settings are provided in the `settings.json` file in this directory.

In the VSCode, add a debug configuration by clicking on the debug icon in the left sidebar and clicking on the gear icon to create a new launch.json file. Copy the content of `launch.json` file in this directory will work.