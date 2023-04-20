BlueFat
=======

This is the prototype implementation of BlueFat.  DO NOT DISTRIBUTE.

A polished version of BlueFat will be open sourced on publication of the
paper.

To use the current prototype, please perform the following steps:

1. Download and setup your local pin installation, version:

        pin-3.22-98547-g7a303a835-gcc-linux

   Other versions may work but this is *UNTESTED*.
2. Copy everything from this folder to your pin directory (<PIN_DIR>)
3. Open the directory <PIN_DIR>/libbluefat" and build the preload library using make.
4. Build the pintool bluefat.cpp available in <PIN_DIR>/source/tools/ManualExamples/.

To use the tool,

        LD_PRELOAD=<PIN_DIR>/libbluefat.so <PIN_DIR>/pin -t <PIN_DIR>/source/tools/ManualExamples/obj-intel64/bluefat.so -- <APPLICATION_BINARY_WITH_ARGS>

Note: the `LD_PRELOAD` must be used or else BlueFat will not detect memory errors.

Tests
-----

The strong attacker model test suite is available under the strong/ directory.

