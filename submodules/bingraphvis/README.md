# bingraphvis

![warning](http://icons.veryicon.com/png/System/Onebit%201-3/warning.png)

The project is in its very early stage, and its under heavy development.

Currently all the functionality I want to support is just "throwed in", but the correct abstraction layers and underlying structure is missing/incomplete.

Expect breaking changes if you rely on the internals of it!

A stable facade API (with limited functionality) is supported for [angr](https://github.com/angr/angr), see `visualize.py` in [angr-utils](https://github.com/axt/angr-utils).

## Purpose

The aim of this project is to provide a generic visualization for the graphs (CFG, CG, DDG, CDG, etc) produced by various binary analysis frameworks.
