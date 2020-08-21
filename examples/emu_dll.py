import argparse

import speakeasy
import logging


def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('emu_dll')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.INFO)

    return logger


def hook_messagebox(emu, api_name, func, params):
    """
    API hook that is installed to intercept MessageBox calls as an example
    Args:
        api_name: The full name including module of the hooked API
        func: the real emulated function provided by the framework
              Users can call this by passing in "params" whenever they choose
        params: the argments passed to the function
    """
    # Call the MessageBox function and print its text string data
    rv = func(params)
    logger = get_logger()

    hWnd, lpText, lpCaption, uType = params

    msg = '%s text: %s' % (api_name, lpText)
    logger.log(logging.INFO, msg)

    # Lets read where the stack pointer is
    logger.log(logging.INFO, 'Stack pointer is at: 0x%x' % (emu.reg_read('esp')))

    return rv


def hook_mem_write(emu, access, address, size, value, ctx):
    """
    Hook that is called whenever memory is written to
    Args:
        access: memory access requested
        address: Memory address that is being written to
        size: Size of the data being written
        value: data that is being written to "address"
    """

    # For a quick example, lets just log writes that occur to the stack
    for mm in emu.get_mem_maps():
        if mm.tag and mm.tag.startswith('emu.stack'):
            start = mm.get_base()
            end = start + mm.get_size()
            if start < address < end:
                logger = get_logger()

                # Get the assembly instruction that did the write
                mnem, op, instr = emu.disasm(emu.reg_read('eip'), 0x20)

                msg = 'Stack written to: instr: %s addr:0x%x' % (instr, address)
                logger.log(logging.INFO, msg)
    return


def main(args):

    # Init the speakeasy object, an optional logger can be supplied
    se = speakeasy.Speakeasy(logger=get_logger())
    module = se.load_module(args.file)

    # Begin emulating the DLL at its defined entry point.
    # If all_entrypoints is set to True, all exports will be emulated sequentially.
    # In this example, lets just run the main entry point and call exports manually.
    se.run_module(module, all_entrypoints=False)

    # Hook user32!MessageBoxA/W and call our function; wild cards are supported here so we can
    # hook both versions with a single hook
    se.add_api_hook(hook_messagebox,
                    'user32',
                    'MessageBox*'
                    )

    # Hook all memory writes as an example
    se.add_mem_write_hook(hook_mem_write)

    # Set up some fake args
    arg0 = 0x0
    arg1 = 0x1
    # Walk the DLLs exports
    for exp in module.get_exports():
        if exp.name == 'emu_test_one':
            # Call an export named 'emu_test_one' and emulate it
            se.call(exp.address, [arg0, arg1])
        if exp.name == 'emu_test_two':
            # Call an export named 'emu_test_two' and emulate it
            se.call(exp.address, [arg0, arg1])


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Emulate a DLL and manually call its exports')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of DLL to emulate')
    args = parser.parse_args()
    main(args)
