import argparse

import speakeasy


class DbgView(speakeasy.Speakeasy):
    '''
    Print debug port prints to the console
    '''

    def __init__(self, debug=False):
        super(DbgView, self).__init__(debug=debug)

    def debug_print_hook(self, emu, api_name, func, params):
        # Call the DbgPrint* function and print the formatted string to the console
        rv = func(params)

        formatted_str = params[0]
        print(formatted_str)

        return rv

    def debug_printex_hook(self, emu, api_name, func, params):
        # Call the DbgPrintEx function and print the formatted string to the console
        rv = func(params)

        formatted_str = params[2]
        print(formatted_str)

        return rv


def main(args):

    dbg = DbgView()
    module = dbg.load_module(args.file)

    dbg.add_api_hook(dbg.debug_print_hook,
                     'ntoskrnl',
                     'DbgPrint'
                     )

    dbg.add_api_hook(dbg.debug_printex_hook,
                     'ntoskrnl',
                     'DbgPrintEx'
                     )

    # Emulate the module
    dbg.run_module(module, all_entrypoints=True)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Print debug port prints to the console')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of driver to emulate')
    args = parser.parse_args()
    main(args)
