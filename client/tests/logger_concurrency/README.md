# Logger concurrency contract

Standalone actual common logger with QtCore/Gui; no application, installer, service,
network or VPN. Linux-only XDG points to an owned QTemporaryDir and the resolved
log path is checked before init. Eight concurrent writers emit512 distinct complete
records; all must appear once in the file. Clear/reopen and init diagnostic reentry
also complete within the CTest deadline. Console is not the record-count oracle.

Prepatch probes returned exit42 with missing/duplicate complete records: the
Qt6.4 run lost505/512; the Qt6.10 run lost4/512 with3duplicates. This is source-level
reproduction, not attribution of a production VPN incident. Parent
owns final component build/test evidence in dist/diagnostics/python-native-client-review-20261021/.
