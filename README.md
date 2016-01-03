## How does it work? ##

You generate some certificates:

    ./voip.py --cert cert.pem --certs certs.pem init --dh-params dhparams.pem

You exchange your public key. Yours is in the `cert.pem` file above, or
whatever you named it. Add your contats to `certs.pem` or whatever you named
it.

You figure out the IP address and port of your contacts.

The callee:

    ./voip.py --cert cert.pem --certs certs.pem s --dh-params dhparams.pem

The caller:

    ./voip.py --cert cert.pem --certs certs.pem c $yourip $yourport

## Why can I hear myself echo on the other end?

Maybe the other guy's speakers are getting picked up by his microphone, and
your voice being fed back to you?

## Why does Python give me a `SyntaxError`?

Requires Python 3.5 or above, because I want PEP 448.

## Why doesn't it work on Ubuntu?

Because I don't have time for the FFmpeg vs libAV tiff.

## Why can't it work better with NAT?

I'm sorry, but that's your problem. I already pollute the code with an extra
exchange to give the public address. You didn't expect much from something that
doesn't even do symmetric RTP, right?

## Why isn't there any form of protocol versioning?

Because I haven't made a stable release, and I really don't care to number
trivial experiments.

## Why isn't there feature X?

Because this is for fun, is intended to solve a specific use case, and isn't
mean to replace SIP (like it was intended to be used, not like the PSTN),
Hangouts, or your favourite VoIP protocol or service.
