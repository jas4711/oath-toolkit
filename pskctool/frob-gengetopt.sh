#!/bin/sh

# frob-gengetopt.sh - Post-process --help output from gengetopt

# Copyright (C) 2026 Simon Josefsson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -e

srcdir=$(dirname $0)

if grep 'display help and exit' $srcdir/pskctool_cmd.c > /dev/null; then
    patch < $srcdir/frob-new.patch
else
    patch < $srcdir/frob-old.patch
fi

exit 0
