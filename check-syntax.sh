#!/bin/sh
pylint -d C0111  -d W0511  -d W0613 -d R0201 -d W0223 -d W0702 -d R0902 psl_typ.py

pylint -d C0111  -d W0511  -d W0613    -d W0702 -d R0902 psl.py
