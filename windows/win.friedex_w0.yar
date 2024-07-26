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

rule win_friedex_w0 {
    meta:
        author = "kevoreilly"
        description = "BitPaymer Payload"
        source = "https://github.com/ctxis/CAPE/blob/a67579f409828928005fc55cfdaae1b5199ea1db/data/yara/CAPE/BitPaymer.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.friedex"
        malpedia_version = "20200304"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
        $antidefender = "TouchMeNot" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
