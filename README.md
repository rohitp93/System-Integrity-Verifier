# System-Integrity-Verifier

The goal of this tool is to detect the file system modifications occurring within a directory tree for
a Linux system. This tool outputs the statistics and warnings about changes of file modifications to
a report file.
Thereby, the tool verifies the integrity of a monitored directory.

Initialization mode:
/usr/bin/python3.5 siv.py -i -D 'monitored_directory' -V 'verification_file' -R 'report_file' -H 'hash'

Verification mode:
/usr/bin/python3.5 siv.py -v -D 'monitored_directory' -V 'verification_file' -R 'report_file'

Help mode:
/usr/bin/python3.5 siv.py -h
