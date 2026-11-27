#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Steven Thomas Holden
#
# Writes the manual page, docs/stratazip.1, from the program's own --version and --help, so the
# page never says something the program does not. Run it after a build whenever --help changes:
#
#   python3 packaging/man.py build/stratazip > docs/stratazip.1
#
# CI runs it too and fails if the page in the repository differs from what the build would write.
import datetime, re, subprocess, sys

exe = sys.argv[1]
ver = subprocess.run([exe, '--version'], capture_output=True, text=True).stdout.strip()
hlp = subprocess.run([exe, '--help'], capture_output=True, text=True)
hlp = (hlp.stdout or hlp.stderr).rstrip('\n').split('\n')
num = re.search(r'StrataZip (\d+\.\d+\.\d+)', ver).group(1)
if hlp and hlp[0].startswith('StrataZip '):
    hlp = hlp[1:]                       # the version line, which the page gives on its own


def esc(t):
    """Text as roff reads it: backslashes doubled, minus signs as \\-, no line read as a request."""
    t = t.replace('\\', '\\e').replace('-', '\\-')
    if t.startswith(('.', "'")):
        t = '\\&' + t
    return t


def para(t):
    return esc(' '.join(t.split()))


out = []
w = out.append
w('.\\" The StrataZip manual page, written by packaging/man.py from the program\'s --help.')
w('.TH STRATAZIP 1 "" "StrataZip %s" "User Commands"' % num)
w('.SH NAME')
w('stratazip \\- measured compression, living archives, traceable data')
w('.SH SYNOPSIS')
w('.B stratazip')
w('[\\fB\\-l\\fR \\fI1\\-10\\fR] [\\fIoptions\\fR] \\fImode\\fR \\fIarguments\\fR')
w('.SH DESCRIPTION')
w(para('StrataZip is an archiver. Each block of your data is tried against several coders, and '
       'the one that measures smallest on that block is kept: context mixing for text, code and '
       'tables, a picture coder for 16-bit images, a waveform coder for 16-bit audio, a two-bit '
       'coder for DNA, LZ for the rest. Every block is checked by a CRC-32 and every file by its '
       'SHA-256 on the way out.'))
w('.PP')
w(para('A folder archive keeps living after it is made: it can be mounted as a drive, synced '
       'with one or several folders, locked and signed, indexed and searched. Every change is a '
       'commit appended to the archive, which can be read as it stood after any of them, and a '
       'crash costs only what was written since the last one. With recovery records (-r) a '
       'damaged archive is mended; without them, damage is found and reported, never decoded '
       'into wrong bytes.'))
w('.SH OPTIONS')
w(para('This is the program\'s own --help, in full.'))
w('.PP')
w('.nf')
w('.ft CR')
for line in hlp:
    w(esc(line) if line else '')
w('.ft R')
w('.fi')
w('.SH EXAMPLES')
ex = [
    ('Compress a table at level 9, and get it back:',
     ['stratazip -l 9 -c prices.csv prices.stz', 'stratazip -d prices.stz prices.csv']),
    ('Archive a folder with 5% recovery records and a signature, then add each night\'s changes:',
     ['stratazip -r 5 -c project backup.stz --sign-with me.key',
      'stratazip --sync project backup.stz --sign-with me.key']),
    ('Take one file back as it stood at a given time:',
     ['stratazip --at 2026-11-24T23:00 --get backup.stz plan.txt plan.txt']),
    ('Mount a folder archive as a writable drive, and unmount it:',
     ['stratazip --mount office.stz ~/office --rw', 'stratazip --umount ~/office']),
    ('Keep two folders in step through one archive, the second over ssh:',
     ['stratazip --sync ~/notes notes.stz --two-way',
      'stratazip --sync ~/notes ssh://nas/notes.stz --two-way']),
    ('Index an archive as it is made, and search it:',
     ['stratazip -c docs docs.stz --index', 'stratazip --search "refund policy" docs.stz --snippets']),
    ('Check an archive, and mend a damaged one into a new copy:',
     ['stratazip -v backup.stz', 'stratazip --repair backup.stz mended.stz']),
]
for say, cmds in ex:
    w('.PP')
    w(esc(say))
    w('.PP')
    w('.RS 4')
    w('.nf')
    for c in cmds:
        w(esc(c))
    w('.fi')
    w('.RE')
w('.SH EXIT STATUS')
w('.TP')
w('.B 0')
w('Done.')
w('.TP')
w('.B 1')
w(para('Failed, or nothing found (--search, --diff, a --salvage that lost a file), or a '
       '--two-way sync that kept a conflict.'))
w('.TP')
w('.B 2')
w(para('Not done: an error or a refusal. The archive is unchanged.'))
w('.TP')
w('.B 3')
w(para('Done, but the archive needs --repair.'))
w('.SH SEE ALSO')
G = 'https://github.com/thomholden/StrataZip/blob/main/'
for say, url in [('The guide: six jobs walked through, with their real output.', G + 'docs/GUIDE.md'),
                 ('The format, byte by byte.', G + 'docs/FORMAT.md'),
                 ('What a lock and a signature protect, and what they do not.', G + 'SECURITY.md'),
                 ('The project.', 'https://stratazip.com')]:
    w('.PP')
    w(esc(say))
    w('.br')
    w('\\%' + esc(url))
w('.SH AUTHOR')
w('Steven Thomas Holden.')
w('.SH COPYRIGHT')
w(para('Copyright (C) 2026 Steven Thomas Holden. StrataZip is free software under the GNU Affero '
       'General Public License, version 3; a commercial licence is also available. The StrataZip '
       'name and logo are trademarks of Steven Thomas Holden.'))
print('\n'.join(out))
