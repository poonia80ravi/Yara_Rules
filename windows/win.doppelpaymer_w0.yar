/*
# Copyright (C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
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
*/

rule win_doppelpaymer_w0 {
    meta:
        author = "kevoreilly"
        description = "DoppelPaymer Payload"
        source = "https://github.com/ctxis/CAPE/blob/9580330546c9cc084c1cef70045ff3cc2db37af8/data/yara/CAPE/DoppelPaymer.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doppelpaymer"
        malpedia_version = "20200304"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $cmd_string = "Setup run\n" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
