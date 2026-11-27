#!/usr/bin/env python3
"""bench/samples.py: the WAV helpers bench/run.sh needs.

    samples.py a.wav b.wav                 exit 0 if the two hold the same samples (format and
                                           every frame), whatever else their headers carry: how
                                           FLAC's round trip is checked, since FLAC drops a WAV's
                                           metadata chunks
    samples.py --join out.wav in.wav ...   the inputs end to end, as one WAV (all the same format)
"""
import sys, wave


def frames(p):
    with wave.open(p, 'rb') as w:
        return (w.getnchannels(), w.getsampwidth(), w.getframerate()), w.readframes(w.getnframes())


if sys.argv[1] == '--join':
    fmt = None
    with wave.open(sys.argv[2], 'wb') as o:
        for p in sys.argv[3:]:
            f, data = frames(p)
            if fmt is None:
                fmt = f; o.setnchannels(f[0]); o.setsampwidth(f[1]); o.setframerate(f[2])
            elif f != fmt:
                sys.exit('%s: format %s, not %s' % (p, f, fmt))
            o.writeframes(data)
else:
    sys.exit(0 if frames(sys.argv[1]) == frames(sys.argv[2]) else 1)
