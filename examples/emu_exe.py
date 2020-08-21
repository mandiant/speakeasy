import argparse

import speakeasy
import logging


def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('emu_exe')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.INFO)

    return logger


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
    logger = get_logger()

    hnd, evt, apcf, apcc, ios, buf, size, offset, key = params

    # Read the buffer containing the file data
    data = emu.mem_read(buf, size)
    logger.log(logging.INFO, data)

    # Write something to the buffer instead
    emu.mem_write(buf, b'A' * size)

    return rv


def main(args):

    # Init the speakeasy object, an optional logger can be supplied
    se = speakeasy.Speakeasy(logger=get_logger())

    # Hook ntdll!NtReadFile so we can modify the returned buffer
    se.add_api_hook(hook_ntreadfile,
                    'ntdll',
                    'NtReadFile'
                    )

    # Load the module into the emulation space
    module = se.load_module(args.file)

    # Begin emulating the EXE at its defined entry point.
    se.run_module(module)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Emulate an EXE and call its entry point')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of EXE to emulate')
    args = parser.parse_args()
    main(args)
