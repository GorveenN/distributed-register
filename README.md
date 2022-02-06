# Distributed register

Distributed register is a form of a distributed storage system. Distributed register consists of N instances, where every server stores some data. As long as more than a half of servers are up and running, the user of distributed register can write new data and read newly written data.

My implementation of distributed register is based on algorithm named `(N, N)-AtomicRegister`.

## `(N, N)-AtomicRegister`

There is a fixed number of instances of the `AtomicRegister` module, `N`, and all instances know about each other. Crashes of individual instances can happen. Every instance can initiate both read and write operations (thus the `(N, N)` in the name of the algorithm). It is assumed that the system is able to progress on operations as long as at least the majority of the instances are working correctly.

The core algorithm, based on the Reliable and Secure Distributed Programming by C. Cachin, R. Guerraoui, L. Rodrigues and modified to suit crash-recovery model, is as follows:


```
Implements:
    (N,N)-AtomicRegister instance nnar.

Uses:
    StubbornBestEffortBroadcast, instance sbeb;
    StubbornLinks, instance sl;

upon event < nnar, Init > do
    (ts, wr, val) := (0, 0, _);
    rid:= 0;
    readlist := [ _ ] `of length` N;
    acklist := [ _ ] `of length` N;
    reading := FALSE;
    writing := FALSE;
    writeval := _;
    readval := _;
    write_phase := FALSE;
    store(wr, ts, val, rid);

upon event < nnar, Recovery > do
    retrieve(wr, ts, val, rid, writing, writeval);
    readlist := [ _ ] `of length` N;
    acklist := [ _ ]  `of length` N;
    reading := FALSE;
    readval := _;
    write_phase := FALSE;
    writing := FALSE;
    writeval := _;

upon event < nnar, Read > do
    rid := rid + 1;
    store(rid);
    readlist := [ _ ] `of length` N;
    acklist := [ _ ] `of length` N;
    reading := TRUE;
    trigger < sbeb, Broadcast | [READ_PROC, rid] >;

upon event < sbeb, Deliver | p [READ_PROC, r] > do
    trigger < sl, Send | p, [VALUE, r, ts, wr, val] >;

upon event <sl, Deliver | q, [VALUE, r, ts', wr', v'] > such that r == rid and !write_phase do
    readlist[q] := (ts', wr', v');
    if #(readlist) > N / 2 and (reading or writing) then
        readlist[self] := (ts, wr, val);
        (maxts, rr, readval) := highest(readlist);
        readlist := [ _ ] `of length` N;
        acklist := [ _ ] `of length` N;
        write_phase := TRUE;
        if reading = TRUE then
            trigger < sbeb, Broadcast | [WRITE_PROC, rid, maxts, rr, readval] >;
        else
            (ts, wr, val) := (maxts + 1, rank(self), writeval);
            store(ts, wr, val);
            trigger < sbeb, Broadcast | [WRITE_PROC, rid, maxts + 1, rank(self), writeval] >;

upon event < nnar, Write | v > do
    rid := rid + 1;
    writeval := v;
    acklist := [ _ ] `of length` N;
    readlist := [ _ ] `of length` N;
    writing := TRUE;
    store(rid);
    trigger < sbeb, Broadcast | [READ_PROC, rid] >;

upon event < sbeb, Deliver | p, [WRITE_PROC, r, ts', wr', v'] > do
    if (ts', wr') > (ts, wr) then
        (ts, wr, val) := (ts', wr', v');
        store(ts, wr, val);
    trigger < sl, Send | p, [ACK, r] >;

upon event < sl, Deliver | q, [ACK, r] > such that r == rid and write_phase do
    acklist[q] := Ack;
    if #(acklist) > N / 2 and (reading or writing) then
        acklist := [ _ ] `of length` N;
        write_phase := FALSE;
        if reading = TRUE then
            reading := FALSE;
            trigger < nnar, ReadReturn | readval >;
        else
            writing := FALSE;
            trigger < nnar, WriteReturn >;
```

The `rank(*)` returns a rank of an instance, which is a static number assigned to an instance. The `highest(*)` returns the largest value ordered by `(timestamp, rank)`.

Each time it starts, it shall try to recover from its stable storage (during the initial run, the stable storage will be empty). Crashes are expected to happen at any point.

## Implementations details

Components of `AtomicRegister` communicate using TCP with custom frame format. 
