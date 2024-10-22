/*
 * YARA rules for MIPS ELF packer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "elf"

rule upx_303_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.03"
		pattern = "????11040000F7272028A4000000E6AC????0D3C2148A00101000B24C2770900????A9154048090000008998030089880400"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 20 28 A4 00 00 00 E6 AC ?? ?? 0D 3C 21 48 A0 01 01 00 0B 24 C2 77 09 00 ?? ?? A9 15 40 48 09 00 00 00 89 98 03 00 89 88 04 00 }
	condition:
		$1 at elf.entry_point
}

rule upx_304_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.04"
		pattern = "??0011040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A0011400001001000B240300899002008E90004A090025482E0101008E90004A090025482E0100008E90004A090025482E0104008424C2770900404809000800E00301002925"
	strings:
		$1 = { ?? 00 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 14 00 00 10 01 00 0B 24 03 00 89 90 02 00 8E 90 00 4A 09 00 25 48 2E 01 01 00 8E 90 00 4A 09 00 25 48 2E 01 00 00 8E 90 00 4A 09 00 25 48 2E 01 04 00 84 24 C2 77 09 00 40 48 09 00 08 00 E0 03 01 00 29 25 }
	condition:
		$1 at elf.entry_point
}

rule upx_3xx_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.xx"
		pattern = "??0011040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B244?00110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0??00110440780F00??0011042178EE01????C01??????E2???00"
	strings:
		$1 = { ?? 00 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 4? 00 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? 00 11 04 40 78 0F 00 ?? 00 11 04 21 78 EE 01 ?? ?? C0 1? ?? ?? ?E 2? ?? 00 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_lzma_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "????11040000F7270000999000FA01240100989007002233C2C8190004082103"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 00 00 99 90 00 FA 01 24 01 00 98 90 07 00 22 33 C2 C8 19 00 04 08 21 03 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2b_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "????11040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B24????110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0????110440780F00????11042178EE01FBFFC011"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 ?? ?? 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? ?? 11 04 40 78 0F 00 ?? ?? 11 04 21 78 EE 01 FB FF C0 11 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2d_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "????11040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B24????110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0????110440780F00????11042178EE010500C015FEFFEE25????11042178CF01"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 ?? ?? 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? ?? 11 04 40 78 0F 00 ?? ?? 11 04 21 78 EE 01 05 00 C0 15 FE FF EE 25 ?? ?? 11 04 21 78 CF 01 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2e_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "????11040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B24????110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0????110440780F00????11042178EE010500C015FEFFEE25????11042178EE01"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 ?? ?? 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? ?? 11 04 40 78 0F 00 ?? ?? 11 04 21 78 EE 01 05 00 C0 15 FE FF EE 25 ?? ?? 11 04 21 78 EE 01 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_lzma_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "0411????27F70000909900002401FA0090980001332200070019C8C203210804"
	strings:
		$1 = { 04 11 ?? ?? 27 F7 00 00 90 99 00 00 24 01 FA 00 90 98 00 01 33 22 00 07 00 19 C8 C2 03 21 08 04 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2b_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "0411????27F7000027BDFFFCAFBF000000A42820ACE600003C0D800001A04821240B00010411????240F000111C00005908E00002484000124C600011000FFF9A0CEFFFF0411????000F78400411????01EE782111C0FFFB"
	strings:
		$1 = { 04 11 ?? ?? 27 F7 00 00 27 BD FF FC AF BF 00 00 00 A4 28 20 AC E6 00 00 3C 0D 80 00 01 A0 48 21 24 0B 00 01 04 11 ?? ?? 24 0F 00 01 11 C0 00 05 90 8E 00 00 24 84 00 01 24 C6 00 01 10 00 FF F9 A0 CE FF FF 04 11 ?? ?? 00 0F 78 40 04 11 ?? ?? 01 EE 78 21 11 C0 FF FB }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2d_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "0411????27F7000027BDFFFCAFBF000000A42820ACE600003C0D800001A04821240B00010411????240F000111C00005908E00002484000124C600011000FFF9A0CEFFFF0411????000F78400411????01EE782115C0000525EEFFFE0411????01CF7821"
	strings:
		$1 = { 04 11 ?? ?? 27 F7 00 00 27 BD FF FC AF BF 00 00 00 A4 28 20 AC E6 00 00 3C 0D 80 00 01 A0 48 21 24 0B 00 01 04 11 ?? ?? 24 0F 00 01 11 C0 00 05 90 8E 00 00 24 84 00 01 24 C6 00 01 10 00 FF F9 A0 CE FF FF 04 11 ?? ?? 00 0F 78 40 04 11 ?? ?? 01 EE 78 21 15 C0 00 05 25 EE FF FE 04 11 ?? ?? 01 CF 78 21 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2e_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "0411????27F7000027BDFFFCAFBF000000A42820ACE600003C0D800001A04821240B00010411????240F000111C00005908E00002484000124C600011000FFF9A0CEFFFF0411????000F78400411????01EE782115C0000525EEFFFE0411????01EE7821"
	strings:
		$1 = { 04 11 ?? ?? 27 F7 00 00 27 BD FF FC AF BF 00 00 00 A4 28 20 AC E6 00 00 3C 0D 80 00 01 A0 48 21 24 0B 00 01 04 11 ?? ?? 24 0F 00 01 11 C0 00 05 90 8E 00 00 24 84 00 01 24 C6 00 01 10 00 FF F9 A0 CE FF FF 04 11 ?? ?? 00 0F 78 40 04 11 ?? ?? 01 EE 78 21 15 C0 00 05 25 EE FF FE 04 11 ?? ?? 01 EE 78 21 }
	condition:
		$1 at elf.entry_point
}
rule mipsBe_lzma_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [LZMA]"
		source = "Made by Jan Neduchal"
		pattern = "04??????27F70000909900002401FA0090980001332200070019C8C2032108042421F16003A1E821AFA1002827AA0020AF"
	strings:
		$h00 = { 04 ?? ?? ?? 27 F7 00 00 90 99 00 00 24 01 FA 00 90 98 00 01 33 22 00 07 00 19 C8 C2 03 21 08 04 24 21 F1 60 03 A1 E8 21 AF A1 00 28 27 AA 00 20 AF }
	condition:
		$h00 at elf.entry_point
}


rule mipsBe_nrv2x_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [NRV2x]"
		source = "Made by Jan Neduchal"
		pattern = "04??????27F7000027BDFFFCAFBF000000A42820ACE600003C0D800001A04821240B000104??????240F000111??????90"
	strings:
		$h00 = { 04 ?? ?? ?? 27 F7 00 00 27 BD FF FC AF BF 00 00 00 A4 28 20 AC E6 00 00 3C 0D 80 00 01 A0 48 21 24 0B 00 01 04 ?? ?? ?? 24 0F 00 01 11 ?? ?? ?? 90 }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_lzma_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [LZMA]"
		source = "Made by Jan Neduchal"
		pattern = "4C??????0000F7270000999000FA01240100989007002233C2C819000408210360F1212421E8A1032800A1AF2000AA272C"
	strings:
		$h00 = { 4C ?? ?? ?? 00 00 F7 27 00 00 99 90 00 FA 01 24 01 00 98 90 07 00 22 33 C2 C8 19 00 04 08 21 03 60 F1 21 24 21 E8 A1 03 28 00 A1 AF 20 00 AA 27 2C }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_nrv2b_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [NRV2B]"
		source = "Made by Jan Neduchal"
		pattern = "B5??????0000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B2438??????01000F2405??????00"
	strings:
		$h00 = { B5 ?? ?? ?? 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 38 ?? ?? ?? 01 00 0F 24 05 ?? ?? ?? 00 }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_nrv2d_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [NRV2D]"
		source = "Made by Jan Neduchal"
		pattern = "BC??????0000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B243F??????01000F2405??????00"
	strings:
		$h00 = { BC ?? ?? ?? 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 3F ?? ?? ?? 01 00 0F 24 05 ?? ?? ?? 00 }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_nrv2e_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [NRV2E]"
		source = "Made by Jan Neduchal"
		pattern = "C0??????0000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B2443??????01000F2405??????00"
	strings:
		$h00 = { C0 ?? ?? ?? 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 43 ?? ?? ?? 01 00 0F 24 05 ?? ?? ?? 00 }
	condition:
		$h00 at elf.entry_point
}


rule mipsBe_lzma_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [LZMA]"
		source = "Made by Jan Neduchal"
		pattern = "04??????27FE0000909900002401FA0090980001332200070019C8C2032108042421F16003A1E821AFA1002827AA0020AF"
	strings:
		$h00 = { 04 ?? ?? ?? 27 FE 00 00 90 99 00 00 24 01 FA 00 90 98 00 01 33 22 00 07 00 19 C8 C2 03 21 08 04 24 21 F1 60 03 A1 E8 21 AF A1 00 28 27 AA 00 20 AF }
	condition:
		$h00 at elf.entry_point
}


rule mipsBe_nrv2x_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [NRV2x]"
		source = "Made by Jan Neduchal"
		pattern = "04??????27FE000027BDFFFCAFBF000000A42820ACE600003C0D800001A04821240B000104??????240F000111??????90"
	strings:
		$h00 = { 04 ?? ?? ?? 27 FE 00 00 27 BD FF FC AF BF 00 00 00 A4 28 20 AC E6 00 00 3C 0D 80 00 01 A0 48 21 24 0B 00 01 04 ?? ?? ?? 24 0F 00 01 11 ?? ?? ?? 90 }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_lzma_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [LZMA]"
		source = "Made by Jan Neduchal"
		pattern = "6D??????0000FE270000999000FA01240100989007002233C2C819000408210360F1212421E8A1032800A1AF2000AA272C"
	strings:
		$h00 = { 6D ?? ?? ?? 00 00 FE 27 00 00 99 90 00 FA 01 24 01 00 98 90 07 00 22 33 C2 C8 19 00 04 08 21 03 60 F1 21 24 21 E8 A1 03 28 00 A1 AF 20 00 AA 27 2C }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_nrv2b_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [NRV2B]"
		source = "Made by Jan Neduchal"
		pattern = "D7??????0000FE27FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B2438??????01000F2405??????00"
	strings:
		$h00 = { D7 ?? ?? ?? 00 00 FE 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 38 ?? ?? ?? 01 00 0F 24 05 ?? ?? ?? 00 }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_nrv2d_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [NRV2D]"
		source = "Made by Jan Neduchal"
		pattern = "DE??????0000FE27FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B243F??????01000F2405??????00"
	strings:
		$h00 = { DE ?? ?? ?? 00 00 FE 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 3F ?? ?? ?? 01 00 0F 24 05 ?? ?? ?? 00 }
	condition:
		$h00 at elf.entry_point
}


rule mipsLe_nrv2e_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [NRV2E]"
		source = "Made by Jan Neduchal"
		pattern = "E2??????0000FE27FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B2443??????01000F2405??????00"
	strings:
		$h00 = { E2 ?? ?? ?? 00 00 FE 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 43 ?? ?? ?? 01 00 0F 24 05 ?? ?? ?? 00 }
	condition:
		$h00 at elf.entry_point
}
