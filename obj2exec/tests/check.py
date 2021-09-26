#!/usr/bin/env python3

import os
import subprocess
import sys


class TestCase:
    def __init__(self, name, return_code, output, which):
        self.name = name
        self.return_code = return_code
        self.output = output
        # which selects whether this test should be run for (r)ef, (l)ink or loa(d)
        self.which = which


all_tests = [
    TestCase("test001", 0, "", "rld"),
    TestCase("test002", 89, "", "rld"),
    TestCase("test003", 54, "", "rld"),
    TestCase("test004", 71, "Hello World!\nHello World!\nNello Borld!\n", "rld"),
    TestCase("test005", 33, "Success: strings match!\n", "rld"),
    TestCase("test006", 100, "Success: strings match!\n", "rld"),
    TestCase("test020", -11, "apple\nHello World\n", "rld"),
    TestCase("test021", -11, "pear\nThis is a read only string\n", "rld"),
    TestCase("test022", -11, "lemon\n", "rld"),
    TestCase("test023", -11, "carrot\n", "rld"),
    TestCase("test024", -11, "orange\n", "rld")
]


def LinkWithLd(iname, oname):
    return subprocess.run(
        ['ld', '-o', f'{oname}', f'{iname}'],
        capture_output=True
    )


def LinkWithObj2Exec(iname, oname):
    return subprocess.run(
        ['../obj2exec', f'{iname}', f'{oname}'],
        capture_output=True
    )


def ExecBySystem(ename):
    return subprocess.run([f'./{ename}'], capture_output=True)


def ExecWithObj2Exec(iname, oname):
    return subprocess.run(
        ['../obj2exec', '-x', f'{iname}', f'{oname}'],
        capture_output=True
    )


def RunTests(mode):
    # Find the path to the directory containing this script
    mydir = os.path.dirname(os.path.realpath(__file__))

    # Set the current working directory to the directory of this script
    os.chdir(mydir)

    # Build the object files
    make = subprocess.run(['make', 'obj'], capture_output=True, check=True)
    print(make.stdout.decode('ascii'))

    # Count passing and total tests
    passcnt = 0
    total = 0

    # Select tests based on mode
    if mode == 'ref':
        tests = [t for t in all_tests if 'r' in t.which]

    if mode == 'link':
        tests = [t for t in all_tests if 'l' in t.which]

    if mode == 'load':
        tests = [t for t in all_tests if 'd' in t.which]

    # Run each test
    for test in tests:
        print(f'===[ {test.name}        ]===')
        success = True

        object_fname = f'{test.name}.o'
        exec_fname = f'{test.name}.{mode}'

        if mode == 'ref' or mode == 'link':
            if mode == 'ref':
                linked = LinkWithLd(object_fname, exec_fname)
            else:
                linked = LinkWithObj2Exec(object_fname, exec_fname)

            print(linked.stdout.decode('ascii'))

            if linked.returncode != 0:
                print('Unsuccessful link!')
                print(linked.stderr.decode('ascii'))
                success = False
            else:
                chmod = subprocess.run(
                    ['chmod', 'u+x', exec_fname],
                    capture_output=True
                )

                if chmod.returncode != 0:
                    print('Unsuccessful chmod!')
                    print(chmod.stderr.decode('ascii'))
                    success = False
                else:
                    run = ExecBySystem(f'{test.name}.{mode}')
        else:
            run = ExecWithObj2Exec(object_fname, exec_fname)

        if success:
            if run.returncode != test.return_code:
                print('Return codes disagree')
                success = False
            if run.stdout.decode('ascii').replace('\x00','') != test.output:
                success = False

        if success:
            print(f'===[ {test.name} passed ]===')
            passcnt += 1
        else:
            print(f'{test.name} failed:')
            print(f'Expected:')
            print(f'  Return code: {test.return_code}')
            print(f'  stdout: "{test.output}"')
            print(f'')
            print(f'Actual:')
            print(f'  Return code: {run.returncode}')
            print(f'  stdout: "{run.stdout.decode("ascii")}"')
            print(f'===[ {test.name} failed ]===')

        total += 1

    print(f'{passcnt}/{total} tests passed')

    return 0


def RunSingle(testfile):
    tests = [t for t in all_tests if testfile in t.name]

    # Find the path to the directory containing this script
    mydir = os.path.dirname(os.path.realpath(__file__))

    # Set the current working directory to the directory of this script
    os.chdir(mydir)

    # Build the object files
    make = subprocess.run(['make', 'obj'], capture_output=True, check=True)
    print(make.stdout.decode('ascii'))
    mode = 'link'

    for test in tests:
        print(f'===[ {test.name}        ]===')
        success = True

        object_fname = f'{test.name}.o'
        exec_fname = f'{test.name}.{mode}'

        linked = LinkWithObj2Exec(object_fname, exec_fname)

        print(linked.stdout.decode('ascii'))

        if linked.returncode != 0:
            print('Unsuccessful link!')
            print(linked.stderr.decode('ascii'))
            success = False
        else:
            chmod = subprocess.run(
                ['chmod', 'u+x', exec_fname],
                capture_output=True
            )

            if chmod.returncode != 0:
                print('Unsuccessful chmod!')
                print(chmod.stderr.decode('ascii'))
                success = False
            else:
                run = ExecBySystem(f'{test.name}.{mode}')

        if success:
            if run.returncode != test.return_code:
                print('Return codes disagree')
                success = False
            if run.stdout.decode('ascii').replace('\x00', '') != test.output:
                success = False

        if success:
            print(f'===[ {test.name} passed ]===')
            print('Running same test for Loader')

            object_fname = f'{test.name}.o'
            exec_fname = f'{test.name}.load'
            run = ExecWithObj2Exec(object_fname, exec_fname)

            if success:
                if run.returncode != test.return_code:
                    print('Return codes disagree')
                    success = False
                if run.stdout.decode('ascii').replace('\x00', '') != test.output:
                    success = False

            if success:
                print(f'===[ {test.name} passed ]===')
            else:
                print(f'{test.name} failed:')
                print(f'Expected:')
                print(f'  Return code: {test.return_code}')
                print(f'  stdout: "{test.output}"')
                print(f'')
                print(f'Actual:')
                print(f'  Return code: {run.returncode}')
                print(f'  stdout: "{run.stdout.decode("ascii")}"')
                print(f'===[ {test.name} failed ]===')
        else:
            print(f'{test.name} failed:')
            print(f'Expected:')
            print(f'  Return code: {test.return_code}')
            print(f'  stdout: "{test.output}"')
            print(f'')
            print(f'Actual:')
            print(f'  Return code: {run.returncode}')
            print(f'  stdout: "{run.stdout.decode("ascii")}"')
            print(f'===[ {test.name} failed ]===')


    return 0


if __name__ == '__main__':
    if(sys.argv[1] in ["ref", "link", "load"]):
        RunTests(sys.argv[1])
    else:
        RunSingle(sys.argv[1])
