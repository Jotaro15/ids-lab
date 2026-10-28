# Security policy

## Supported versions

The project is in early development. Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

Use the **Report a vulnerability** button in the **Security** tab of this repository. It opens a private discussion that only the maintainer can see. If the button is not available, contact me through the email or links on my GitHub profile.

Please include what you found, how to reproduce it, and what you think the impact is. I will answer as soon as I can and keep you informed until it is fixed.

## What counts as a vulnerability

Examples:

- A way to make a scenario target something outside the lab network.
- A container escape or an unintended exposure of a port, volume or the Docker socket.
- Code execution through a crafted pcap file, scenario file or model file.
- A secret committed to the repository.

## What does not count

The victim container in the lab uses weak accounts and passwords on purpose, because the brute force scenario needs something to find. They only exist inside an isolated network and are not a vulnerability.

## Responsible use

This project generates attack traffic. Run it only on your own machine, inside the lab it creates. Never point it at systems you do not own or have written permission to test.
