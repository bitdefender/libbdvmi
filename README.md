# Libbdvmi

(c) 2015-2021 Bitdefender SRL

## Usage

Please use Xen 4.6 or newer. To test the library, issue:
```
$ ./bootstrap
$ ./configure
$ make
```
This will build the library and the test under examples/.

To build the library with KVM support (if libkvmi is installed), issue:
```
$ ./configure --enable-kvmi
```

To see the test in action, run (as root):
```
# ./hookguest
```
in the `examples/` subdirectory, then simply start a Xen domain up.

The application can be shut down at any time via `^C`.
