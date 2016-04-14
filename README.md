scapy-pgp
=========

A scapy layer for parsing OpenPGP formatted files. This may seems non-intuitive,
but the specification (rfc4880) describes the format in terms of 'packets', making
scapy a natural fit for parsing it.