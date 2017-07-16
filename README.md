# AARNet TSP

Simple AARNet IPv6 Broker TSP client written in ruby

## Creating your tunnel

    tsp --username username --password password --action create

From my experience this only needs to be done every time your IPv4 address
changes. AARNet don't care about keepalive.

## Deleting your tunnel

    tsp --username username --password password --action delete

This always seems to return `310 Server side error`

## Tunnel info

    tsp --username username --password password --action info

This always seems to return `310 Server side error`
