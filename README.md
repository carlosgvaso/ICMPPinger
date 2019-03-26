ICMPPinger
==========

ICMP pinger application.

**Author**: Jose Carlos Martinez Garcia-Vaso <carlosgvaso@gmail.com> @carlosgvaso

**Contributions**: Based on the source code provided by Ramesh Yerraballi.

> Copyright :copyright: 2019 of Jose Carlos Martinez Garcia-Vaso.


Usage
-----

Run the Python2 interpreter with admin privileges, then:

```python
import ICMPPinger
ICMPPinger.ping("<URL or IP>", timeout=<time in sec>)
```

The `timeout` parameter is optional, and it will default to 1sec if it is not specified. You can also run a one-liner 
on the shell:

```bash
sudo python -c 'import ICMPPinger; ICMPPinger.ping("<URL or IP>", timeout=<time in sec>)'
```

Running the script from the shell as shown below will ping the test case `www.google.com` with a default timeout of 
1sec:

```bash
sudo python ICMPPinger.py
```