import argparse
import logging

import speakeasy

logger = logging.getLogger(__name__)


def hook_ntreadfile(emu, api_name, func, params):
    """
    API hook that is installed to intercept MessageBox calls as an example
    Args:
        api_name: The full name including module of the hooked API
        func: the real emulated function provided by the framework
              Users can call this by passing in "params" whenever they choose
        params: the argments passed to the function
    """
    # Call the NtReadFile function
    rv = func(params)

    hnd, evt, apcf, apcc, ios, buf, size, offset, key = params

    # Read the buffer containing the file data
    data = emu.mem_read(buf, size)
    logger.info(data)

    # Write something to the buffer instead
    emu.mem_write(buf, b"A" * size)

    return rv


def main(args):

    # Init the speakeasy object
    se = speakeasy.Speakeasy()

    # Hook ntdll!NtReadFile so we can modify the returned buffer
    se.add_api_hook(hook_ntreadfile, "ntdll", "NtReadFile")

    # Load the module into the emulation space
    module = se.load_module(args.file)

    # Begin emulating the EXE at its defined entry point.
    se.run_module(module)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emulate an EXE and call its entry point")
    parser.add_argument("-f", "--file", action="store", dest="file", required=True, help="Path of EXE to emulate")
    args = parser.parse_args()
    main(args)
