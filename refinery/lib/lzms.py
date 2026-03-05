from __future__ import annotations

import struct as _struct

from refinery.lib.types import buf
from refinery.lib.decompression import (
    DECODE_TABLE_LENGTH_MASK,
    DECODE_TABLE_SYMBOL_SHIFT,
    make_huffman_decode_table,
)

LZMS_PROB_BITS                  = 6                    # noqa
LZMS_PROB_DENOM                 = 1 << LZMS_PROB_BITS  # noqa
LZMS_INITIAL_PROB               = 48                   # noqa
LZMS_INITIAL_BITS               = 0x0000000055555555   # noqa

LZMS_NUM_LZ_REPS                = 3         # noqa
LZMS_NUM_DELTA_REPS             = 3         # noqa

LZMS_NUM_MAIN_PROBS             = 16        # noqa
LZMS_NUM_MATCH_PROBS            = 32        # noqa
LZMS_NUM_LZ_PROBS               = 64        # noqa
LZMS_NUM_LZ_REP_PROBS           = 64        # noqa
LZMS_NUM_DELTA_PROBS            = 64        # noqa
LZMS_NUM_DELTA_REP_PROBS        = 64        # noqa

LZMS_NUM_LITERAL_SYMS           = 256       # noqa
LZMS_NUM_LENGTH_SYMS            = 54        # noqa
LZMS_NUM_DELTA_POWER_SYMS       = 8         # noqa
LZMS_MAX_NUM_OFFSET_SYMS        = 799       # noqa
LZMS_MAX_CODEWORD_LENGTH        = 15        # noqa

LZMS_LITERAL_REBUILD_FREQ       = 1024      # noqa
LZMS_LZ_OFFSET_REBUILD_FREQ     = 1024      # noqa
LZMS_LENGTH_REBUILD_FREQ        = 512       # noqa
LZMS_DELTA_OFFSET_REBUILD_FREQ  = 1024      # noqa
LZMS_DELTA_POWER_REBUILD_FREQ   = 512       # noqa

LZMS_LITERAL_TABLEBITS          = 10        # noqa
LZMS_LENGTH_TABLEBITS           = 9         # noqa
LZMS_LZ_OFFSET_TABLEBITS        = 11        # noqa
LZMS_DELTA_OFFSET_TABLEBITS     = 11        # noqa
LZMS_DELTA_POWER_TABLEBITS      = 7         # noqa

LZMS_X86_ID_WINDOW_SIZE         = 65535     # noqa
LZMS_X86_MAX_TRANSLATION_OFF    = 1023      # noqa

LZMS_OFFSET_SLOT_BASE = [
    0x00000001, 0x00000002, 0x00000003, 0x00000004,
    0x00000005, 0x00000006, 0x00000007, 0x00000008,
    0x00000009, 0x0000000D, 0x00000011, 0x00000015,
    0x00000019, 0x0000001D, 0x00000021, 0x00000025,
    0x00000029, 0x0000002D, 0x00000035, 0x0000003D,
    0x00000045, 0x0000004D, 0x00000055, 0x0000005D,
    0x00000065, 0x00000075, 0x00000085, 0x00000095,
    0x000000A5, 0x000000B5, 0x000000C5, 0x000000D5,
    0x000000E5, 0x000000F5, 0x00000105, 0x00000125,
    0x00000145, 0x00000165, 0x00000185, 0x000001A5,
    0x000001C5, 0x000001E5, 0x00000205, 0x00000225,
    0x00000245, 0x00000265, 0x00000285, 0x000002A5,
    0x000002C5, 0x000002E5, 0x00000325, 0x00000365,
    0x000003A5, 0x000003E5, 0x00000425, 0x00000465,
    0x000004A5, 0x000004E5, 0x00000525, 0x00000565,
    0x000005A5, 0x000005E5, 0x00000625, 0x00000665,
    0x000006A5, 0x00000725, 0x000007A5, 0x00000825,
    0x000008A5, 0x00000925, 0x000009A5, 0x00000A25,
    0x00000AA5, 0x00000B25, 0x00000BA5, 0x00000C25,
    0x00000CA5, 0x00000D25, 0x00000DA5, 0x00000E25,
    0x00000EA5, 0x00000F25, 0x00000FA5, 0x00001025,
    0x000010A5, 0x000011A5, 0x000012A5, 0x000013A5,
    0x000014A5, 0x000015A5, 0x000016A5, 0x000017A5,
    0x000018A5, 0x000019A5, 0x00001AA5, 0x00001BA5,
    0x00001CA5, 0x00001DA5, 0x00001EA5, 0x00001FA5,
    0x000020A5, 0x000021A5, 0x000022A5, 0x000023A5,
    0x000024A5, 0x000026A5, 0x000028A5, 0x00002AA5,
    0x00002CA5, 0x00002EA5, 0x000030A5, 0x000032A5,
    0x000034A5, 0x000036A5, 0x000038A5, 0x00003AA5,
    0x00003CA5, 0x00003EA5, 0x000040A5, 0x000042A5,
    0x000044A5, 0x000046A5, 0x000048A5, 0x00004AA5,
    0x00004CA5, 0x00004EA5, 0x000050A5, 0x000052A5,
    0x000054A5, 0x000056A5, 0x000058A5, 0x00005AA5,
    0x00005CA5, 0x00005EA5, 0x000060A5, 0x000064A5,
    0x000068A5, 0x00006CA5, 0x000070A5, 0x000074A5,
    0x000078A5, 0x00007CA5, 0x000080A5, 0x000084A5,
    0x000088A5, 0x00008CA5, 0x000090A5, 0x000094A5,
    0x000098A5, 0x00009CA5, 0x0000A0A5, 0x0000A4A5,
    0x0000A8A5, 0x0000ACA5, 0x0000B0A5, 0x0000B4A5,
    0x0000B8A5, 0x0000BCA5, 0x0000C0A5, 0x0000C4A5,
    0x0000C8A5, 0x0000CCA5, 0x0000D0A5, 0x0000D4A5,
    0x0000D8A5, 0x0000DCA5, 0x0000E0A5, 0x0000E4A5,
    0x0000ECA5, 0x0000F4A5, 0x0000FCA5, 0x000104A5,
    0x00010CA5, 0x000114A5, 0x00011CA5, 0x000124A5,
    0x00012CA5, 0x000134A5, 0x00013CA5, 0x000144A5,
    0x00014CA5, 0x000154A5, 0x00015CA5, 0x000164A5,
    0x00016CA5, 0x000174A5, 0x00017CA5, 0x000184A5,
    0x00018CA5, 0x000194A5, 0x00019CA5, 0x0001A4A5,
    0x0001ACA5, 0x0001B4A5, 0x0001BCA5, 0x0001C4A5,
    0x0001CCA5, 0x0001D4A5, 0x0001DCA5, 0x0001E4A5,
    0x0001ECA5, 0x0001F4A5, 0x0001FCA5, 0x000204A5,
    0x00020CA5, 0x000214A5, 0x00021CA5, 0x000224A5,
    0x000234A5, 0x000244A5, 0x000254A5, 0x000264A5,
    0x000274A5, 0x000284A5, 0x000294A5, 0x0002A4A5,
    0x0002B4A5, 0x0002C4A5, 0x0002D4A5, 0x0002E4A5,
    0x0002F4A5, 0x000304A5, 0x000314A5, 0x000324A5,
    0x000334A5, 0x000344A5, 0x000354A5, 0x000364A5,
    0x000374A5, 0x000384A5, 0x000394A5, 0x0003A4A5,
    0x0003B4A5, 0x0003C4A5, 0x0003D4A5, 0x0003E4A5,
    0x0003F4A5, 0x000404A5, 0x000414A5, 0x000424A5,
    0x000434A5, 0x000444A5, 0x000454A5, 0x000464A5,
    0x000474A5, 0x000484A5, 0x000494A5, 0x0004A4A5,
    0x0004B4A5, 0x0004C4A5, 0x0004E4A5, 0x000504A5,
    0x000524A5, 0x000544A5, 0x000564A5, 0x000584A5,
    0x0005A4A5, 0x0005C4A5, 0x0005E4A5, 0x000604A5,
    0x000624A5, 0x000644A5, 0x000664A5, 0x000684A5,
    0x0006A4A5, 0x0006C4A5, 0x0006E4A5, 0x000704A5,
    0x000724A5, 0x000744A5, 0x000764A5, 0x000784A5,
    0x0007A4A5, 0x0007C4A5, 0x0007E4A5, 0x000804A5,
    0x000824A5, 0x000844A5, 0x000864A5, 0x000884A5,
    0x0008A4A5, 0x0008C4A5, 0x0008E4A5, 0x000904A5,
    0x000924A5, 0x000944A5, 0x000964A5, 0x000984A5,
    0x0009A4A5, 0x0009C4A5, 0x0009E4A5, 0x000A04A5,
    0x000A24A5, 0x000A44A5, 0x000A64A5, 0x000AA4A5,
    0x000AE4A5, 0x000B24A5, 0x000B64A5, 0x000BA4A5,
    0x000BE4A5, 0x000C24A5, 0x000C64A5, 0x000CA4A5,
    0x000CE4A5, 0x000D24A5, 0x000D64A5, 0x000DA4A5,
    0x000DE4A5, 0x000E24A5, 0x000E64A5, 0x000EA4A5,
    0x000EE4A5, 0x000F24A5, 0x000F64A5, 0x000FA4A5,
    0x000FE4A5, 0x001024A5, 0x001064A5, 0x0010A4A5,
    0x0010E4A5, 0x001124A5, 0x001164A5, 0x0011A4A5,
    0x0011E4A5, 0x001224A5, 0x001264A5, 0x0012A4A5,
    0x0012E4A5, 0x001324A5, 0x001364A5, 0x0013A4A5,
    0x0013E4A5, 0x001424A5, 0x001464A5, 0x0014A4A5,
    0x0014E4A5, 0x001524A5, 0x001564A5, 0x0015A4A5,
    0x0015E4A5, 0x001624A5, 0x001664A5, 0x0016A4A5,
    0x0016E4A5, 0x001724A5, 0x001764A5, 0x0017A4A5,
    0x0017E4A5, 0x001824A5, 0x001864A5, 0x0018A4A5,
    0x0018E4A5, 0x001924A5, 0x001964A5, 0x0019E4A5,
    0x001A64A5, 0x001AE4A5, 0x001B64A5, 0x001BE4A5,
    0x001C64A5, 0x001CE4A5, 0x001D64A5, 0x001DE4A5,
    0x001E64A5, 0x001EE4A5, 0x001F64A5, 0x001FE4A5,
    0x002064A5, 0x0020E4A5, 0x002164A5, 0x0021E4A5,
    0x002264A5, 0x0022E4A5, 0x002364A5, 0x0023E4A5,
    0x002464A5, 0x0024E4A5, 0x002564A5, 0x0025E4A5,
    0x002664A5, 0x0026E4A5, 0x002764A5, 0x0027E4A5,
    0x002864A5, 0x0028E4A5, 0x002964A5, 0x0029E4A5,
    0x002A64A5, 0x002AE4A5, 0x002B64A5, 0x002BE4A5,
    0x002C64A5, 0x002CE4A5, 0x002D64A5, 0x002DE4A5,
    0x002E64A5, 0x002EE4A5, 0x002F64A5, 0x002FE4A5,
    0x003064A5, 0x0030E4A5, 0x003164A5, 0x0031E4A5,
    0x003264A5, 0x0032E4A5, 0x003364A5, 0x0033E4A5,
    0x003464A5, 0x0034E4A5, 0x003564A5, 0x0035E4A5,
    0x003664A5, 0x0036E4A5, 0x003764A5, 0x0037E4A5,
    0x003864A5, 0x0038E4A5, 0x003964A5, 0x0039E4A5,
    0x003A64A5, 0x003AE4A5, 0x003B64A5, 0x003BE4A5,
    0x003C64A5, 0x003CE4A5, 0x003D64A5, 0x003DE4A5,
    0x003EE4A5, 0x003FE4A5, 0x0040E4A5, 0x0041E4A5,
    0x0042E4A5, 0x0043E4A5, 0x0044E4A5, 0x0045E4A5,
    0x0046E4A5, 0x0047E4A5, 0x0048E4A5, 0x0049E4A5,
    0x004AE4A5, 0x004BE4A5, 0x004CE4A5, 0x004DE4A5,
    0x004EE4A5, 0x004FE4A5, 0x0050E4A5, 0x0051E4A5,
    0x0052E4A5, 0x0053E4A5, 0x0054E4A5, 0x0055E4A5,
    0x0056E4A5, 0x0057E4A5, 0x0058E4A5, 0x0059E4A5,
    0x005AE4A5, 0x005BE4A5, 0x005CE4A5, 0x005DE4A5,
    0x005EE4A5, 0x005FE4A5, 0x0060E4A5, 0x0061E4A5,
    0x0062E4A5, 0x0063E4A5, 0x0064E4A5, 0x0065E4A5,
    0x0066E4A5, 0x0067E4A5, 0x0068E4A5, 0x0069E4A5,
    0x006AE4A5, 0x006BE4A5, 0x006CE4A5, 0x006DE4A5,
    0x006EE4A5, 0x006FE4A5, 0x0070E4A5, 0x0071E4A5,
    0x0072E4A5, 0x0073E4A5, 0x0074E4A5, 0x0075E4A5,
    0x0076E4A5, 0x0077E4A5, 0x0078E4A5, 0x0079E4A5,
    0x007AE4A5, 0x007BE4A5, 0x007CE4A5, 0x007DE4A5,
    0x007EE4A5, 0x007FE4A5, 0x0080E4A5, 0x0081E4A5,
    0x0082E4A5, 0x0083E4A5, 0x0084E4A5, 0x0085E4A5,
    0x0086E4A5, 0x0087E4A5, 0x0088E4A5, 0x0089E4A5,
    0x008AE4A5, 0x008BE4A5, 0x008CE4A5, 0x008DE4A5,
    0x008FE4A5, 0x0091E4A5, 0x0093E4A5, 0x0095E4A5,
    0x0097E4A5, 0x0099E4A5, 0x009BE4A5, 0x009DE4A5,
    0x009FE4A5, 0x00A1E4A5, 0x00A3E4A5, 0x00A5E4A5,
    0x00A7E4A5, 0x00A9E4A5, 0x00ABE4A5, 0x00ADE4A5,
    0x00AFE4A5, 0x00B1E4A5, 0x00B3E4A5, 0x00B5E4A5,
    0x00B7E4A5, 0x00B9E4A5, 0x00BBE4A5, 0x00BDE4A5,
    0x00BFE4A5, 0x00C1E4A5, 0x00C3E4A5, 0x00C5E4A5,
    0x00C7E4A5, 0x00C9E4A5, 0x00CBE4A5, 0x00CDE4A5,
    0x00CFE4A5, 0x00D1E4A5, 0x00D3E4A5, 0x00D5E4A5,
    0x00D7E4A5, 0x00D9E4A5, 0x00DBE4A5, 0x00DDE4A5,
    0x00DFE4A5, 0x00E1E4A5, 0x00E3E4A5, 0x00E5E4A5,
    0x00E7E4A5, 0x00E9E4A5, 0x00EBE4A5, 0x00EDE4A5,
    0x00EFE4A5, 0x00F1E4A5, 0x00F3E4A5, 0x00F5E4A5,
    0x00F7E4A5, 0x00F9E4A5, 0x00FBE4A5, 0x00FDE4A5,
    0x00FFE4A5, 0x0101E4A5, 0x0103E4A5, 0x0105E4A5,
    0x0107E4A5, 0x0109E4A5, 0x010BE4A5, 0x010DE4A5,
    0x010FE4A5, 0x0111E4A5, 0x0113E4A5, 0x0115E4A5,
    0x0117E4A5, 0x0119E4A5, 0x011BE4A5, 0x011DE4A5,
    0x011FE4A5, 0x0121E4A5, 0x0123E4A5, 0x0125E4A5,
    0x0127E4A5, 0x0129E4A5, 0x012BE4A5, 0x012DE4A5,
    0x012FE4A5, 0x0131E4A5, 0x0133E4A5, 0x0135E4A5,
    0x0137E4A5, 0x013BE4A5, 0x013FE4A5, 0x0143E4A5,
    0x0147E4A5, 0x014BE4A5, 0x014FE4A5, 0x0153E4A5,
    0x0157E4A5, 0x015BE4A5, 0x015FE4A5, 0x0163E4A5,
    0x0167E4A5, 0x016BE4A5, 0x016FE4A5, 0x0173E4A5,
    0x0177E4A5, 0x017BE4A5, 0x017FE4A5, 0x0183E4A5,
    0x0187E4A5, 0x018BE4A5, 0x018FE4A5, 0x0193E4A5,
    0x0197E4A5, 0x019BE4A5, 0x019FE4A5, 0x01A3E4A5,
    0x01A7E4A5, 0x01ABE4A5, 0x01AFE4A5, 0x01B3E4A5,
    0x01B7E4A5, 0x01BBE4A5, 0x01BFE4A5, 0x01C3E4A5,
    0x01C7E4A5, 0x01CBE4A5, 0x01CFE4A5, 0x01D3E4A5,
    0x01D7E4A5, 0x01DBE4A5, 0x01DFE4A5, 0x01E3E4A5,
    0x01E7E4A5, 0x01EBE4A5, 0x01EFE4A5, 0x01F3E4A5,
    0x01F7E4A5, 0x01FBE4A5, 0x01FFE4A5, 0x0203E4A5,
    0x0207E4A5, 0x020BE4A5, 0x020FE4A5, 0x0213E4A5,
    0x0217E4A5, 0x021BE4A5, 0x021FE4A5, 0x0223E4A5,
    0x0227E4A5, 0x022BE4A5, 0x022FE4A5, 0x0233E4A5,
    0x0237E4A5, 0x023BE4A5, 0x023FE4A5, 0x0243E4A5,
    0x0247E4A5, 0x024BE4A5, 0x024FE4A5, 0x0253E4A5,
    0x0257E4A5, 0x025BE4A5, 0x025FE4A5, 0x0263E4A5,
    0x0267E4A5, 0x026BE4A5, 0x026FE4A5, 0x0273E4A5,
    0x0277E4A5, 0x027BE4A5, 0x027FE4A5, 0x0283E4A5,
    0x0287E4A5, 0x028BE4A5, 0x028FE4A5, 0x0293E4A5,
    0x0297E4A5, 0x029BE4A5, 0x029FE4A5, 0x02A3E4A5,
    0x02A7E4A5, 0x02ABE4A5, 0x02AFE4A5, 0x02B3E4A5,
    0x02BBE4A5, 0x02C3E4A5, 0x02CBE4A5, 0x02D3E4A5,
    0x02DBE4A5, 0x02E3E4A5, 0x02EBE4A5, 0x02F3E4A5,
    0x02FBE4A5, 0x0303E4A5, 0x030BE4A5, 0x0313E4A5,
    0x031BE4A5, 0x0323E4A5, 0x032BE4A5, 0x0333E4A5,
    0x033BE4A5, 0x0343E4A5, 0x034BE4A5, 0x0353E4A5,
    0x035BE4A5, 0x0363E4A5, 0x036BE4A5, 0x0373E4A5,
    0x037BE4A5, 0x0383E4A5, 0x038BE4A5, 0x0393E4A5,
    0x039BE4A5, 0x03A3E4A5, 0x03ABE4A5, 0x03B3E4A5,
    0x03BBE4A5, 0x03C3E4A5, 0x03CBE4A5, 0x03D3E4A5,
    0x03DBE4A5, 0x03E3E4A5, 0x03EBE4A5, 0x03F3E4A5,
    0x03FBE4A5, 0x0403E4A5, 0x040BE4A5, 0x0413E4A5,
    0x041BE4A5, 0x0423E4A5, 0x042BE4A5, 0x0433E4A5,
    0x043BE4A5, 0x0443E4A5, 0x044BE4A5, 0x0453E4A5,
    0x045BE4A5, 0x0463E4A5, 0x046BE4A5, 0x0473E4A5,
    0x047BE4A5, 0x0483E4A5, 0x048BE4A5, 0x0493E4A5,
    0x049BE4A5, 0x04A3E4A5, 0x04ABE4A5, 0x04B3E4A5,
    0x04BBE4A5, 0x04C3E4A5, 0x04CBE4A5, 0x04D3E4A5,
    0x04DBE4A5, 0x04E3E4A5, 0x04EBE4A5, 0x04F3E4A5,
    0x04FBE4A5, 0x0503E4A5, 0x050BE4A5, 0x0513E4A5,
    0x051BE4A5, 0x0523E4A5, 0x052BE4A5, 0x0533E4A5,
    0x053BE4A5, 0x0543E4A5, 0x054BE4A5, 0x0553E4A5,
    0x055BE4A5, 0x0563E4A5, 0x056BE4A5, 0x0573E4A5,
    0x057BE4A5, 0x0583E4A5, 0x058BE4A5, 0x0593E4A5,
    0x059BE4A5, 0x05A3E4A5, 0x05ABE4A5, 0x05B3E4A5,
    0x05BBE4A5, 0x05C3E4A5, 0x05CBE4A5, 0x05D3E4A5,
    0x05DBE4A5, 0x05E3E4A5, 0x05EBE4A5, 0x05F3E4A5,
    0x05FBE4A5, 0x060BE4A5, 0x061BE4A5, 0x062BE4A5,
    0x063BE4A5, 0x064BE4A5, 0x065BE4A5, 0x465BE4A5,
]

LZMS_EXTRA_OFFSET_BITS = [
    0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2,
    2 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 4 , 4 , 4 , 4 , 4 , 4 , 4 , 4,
    4 , 4 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5,
    5 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6,
    7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7,
    7 , 7 , 7 , 7 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8,
    8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9,
    9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9,
    9 , 9 , 9 , 9 , 9 , 9 , 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 30,
]

LZMS_LENGTH_SLOT_BASE = [
    0x00000001, 0x00000002, 0x00000003, 0x00000004,
    0x00000005, 0x00000006, 0x00000007, 0x00000008,
    0x00000009, 0x0000000A, 0x0000000B, 0x0000000C,
    0x0000000D, 0x0000000E, 0x0000000F, 0x00000010,
    0x00000011, 0x00000012, 0x00000013, 0x00000014,
    0x00000015, 0x00000016, 0x00000017, 0x00000018,
    0x00000019, 0x0000001A, 0x0000001B, 0x0000001D,
    0x0000001F, 0x00000021, 0x00000023, 0x00000027,
    0x0000002B, 0x0000002F, 0x00000033, 0x00000037,
    0x0000003B, 0x00000043, 0x0000004B, 0x00000053,
    0x0000005B, 0x0000006B, 0x0000007B, 0x0000008B,
    0x0000009B, 0x000000AB, 0x000000CB, 0x000000EB,
    0x0000012B, 0x000001AB, 0x000002AB, 0x000004AB,
    0x000008AB, 0x000108AB,
]

LZMS_EXTRA_LENGTH_BITS = [
    0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,
    0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,
    0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,
    0 , 0 , 1 , 1 , 1 , 1 , 2 , 2 ,
    2 , 2 , 2 , 2 , 3 , 3 , 3 , 3 ,
    4 , 4 , 4 , 4 , 4 , 5 , 5 , 6 ,
    7 , 8 , 9 , 10, 16, 30,
]


def _lzms_get_num_offset_slots(uncompressed_size: int) -> int:
    if uncompressed_size < 2:
        return 0
    target = uncompressed_size - 1
    lo, hi = 0, LZMS_MAX_NUM_OFFSET_SYMS - 1
    while True:
        mid = (lo + hi) // 2
        if target >= LZMS_OFFSET_SLOT_BASE[mid]:
            if target < LZMS_OFFSET_SLOT_BASE[mid + 1]:
                return mid + 1
            lo = mid + 1
        else:
            hi = mid - 1


class LzmsProbEntry:
    __slots__ = 'num_recent_zero_bits', 'recent_bits'

    def __init__(self):
        self.num_recent_zero_bits = LZMS_INITIAL_PROB
        self.recent_bits = LZMS_INITIAL_BITS

    def update(self, bit: int):
        delta = int(self.recent_bits >> (LZMS_PROB_DENOM - 1)) - bit
        self.num_recent_zero_bits += delta
        self.recent_bits = ((self.recent_bits << 1) | bit) & ((1 << LZMS_PROB_DENOM) - 1)

    @property
    def probability(self) -> int:
        p = self.num_recent_zero_bits
        if p == 0:
            p = 1
        if p == LZMS_PROB_DENOM:
            p = LZMS_PROB_DENOM - 1
        return p


class LzmsInputBitStream:
    __slots__ = '_data', '_pos', '_bitbuf', '_bitcount'

    def __init__(self, data: buf):
        self._data = data
        self._pos = len(data)
        self._bitbuf = 0
        self._bitcount = 0

    def ensure(self, n: int):
        while self._bitcount < n:
            if self._pos < 2:
                return
            self._pos -= 2
            word = _struct.unpack_from('<H', self._data, self._pos)[0]
            avail = 64 - self._bitcount
            self._bitbuf |= word << (avail - 16)
            self._bitcount += 16

    def peek(self, n: int) -> int:
        return (self._bitbuf >> 1) >> (63 - n)

    def remove(self, n: int):
        self._bitbuf <<= n
        self._bitbuf &= (1 << 64) - 1
        self._bitcount -= n

    def read(self, n: int) -> int:
        if n == 0:
            return 0
        self.ensure(n)
        val = self.peek(n)
        self.remove(n)
        return val


class LzmsRangeDecoder:
    __slots__ = '_data', '_pos', '_end', 'range', 'code'

    def __init__(self, data: buf):
        self._data = data
        self._pos = 0
        self._end = len(data)
        hi = self._read_u16()
        lo = self._read_u16()
        self.range = 0xFFFFFFFF
        self.code = (hi << 16) | lo

    def _read_u16(self) -> int:
        if self._pos + 2 > self._end:
            return 0
        val = _struct.unpack_from('<H', self._data, self._pos)[0]
        self._pos += 2
        return val

    def _normalize(self):
        if not (self.range & 0xFFFF0000):
            self.range = (self.range << 16) & 0xFFFFFFFF
            self.code = ((self.code << 16) | self._read_u16()) & 0xFFFFFFFF

    def decode_bit(self, state: list, num_states: int, probs: list) -> int:
        entry = probs[state[0]]
        state[0] = (state[0] << 1) & (num_states - 1)
        prob = entry.probability
        self._normalize()
        bound = (self.range >> LZMS_PROB_BITS) * prob
        if self.code < bound:
            self.range = bound
            entry.update(0)
            return 0
        else:
            self.range -= bound
            self.code -= bound
            entry.update(1)
            state[0] |= 1
            return 1


class LzmsHuffmanDecoder:
    __slots__ = (
        '_bitstream',
        '_num_syms',
        '_rebuild_freq',
        '_freqs',
        '_syms_until_rebuild',
        '_decode_table',
        '_table_bits',
    )

    def __init__(
        self,
        bitstream: LzmsInputBitStream,
        num_syms: int,
        rebuild_freq: int,
        table_bits: int
    ):
        self._bitstream = bitstream
        self._num_syms = num_syms
        self._rebuild_freq = rebuild_freq
        self._table_bits = table_bits
        self._freqs = [1] * num_syms
        self._syms_until_rebuild = 0
        self._decode_table = None
        self._build()

    def _build(self):
        lengths = self._compute_lengths()
        try:
            self._decode_table = make_huffman_decode_table(
                lengths, self._table_bits, LZMS_MAX_CODEWORD_LENGTH)
        except Exception:
            self._decode_table = None
        self._syms_until_rebuild = self._rebuild_freq

    def _compute_lengths(self) -> bytearray:
        n = self._num_syms
        freq = self._freqs
        lengths = bytearray(n)

        if n <= 1:
            if n == 1:
                lengths[0] = 1
            return lengths

        symbols = sorted(range(n), key=lambda s: (freq[s], s))
        leaf_freqs = [freq[s] for s in symbols]
        q1_head = 0
        q2: list[tuple[int, int]] = []
        q2_head = 0
        parent = [0] * (2 * n)
        is_leaf = [False] * (2 * n)
        node_count = n

        for i in range(n):
            is_leaf[i] = True

        def _pick_min():
            nonlocal q1_head, q2_head
            q1_avail = q1_head < n
            q2_avail = q2_head < len(q2)
            if q1_avail and q2_avail:
                f1 = leaf_freqs[q1_head]
                f2 = q2[q2_head][0]
                if f1 <= f2:
                    idx = q1_head
                    q1_head += 1
                    return f1, idx
                else:
                    f, idx = q2[q2_head]
                    q2_head += 1
                    return f, idx
            elif q1_avail:
                idx = q1_head
                q1_head += 1
                return leaf_freqs[idx], idx
            else:
                f, idx = q2[q2_head]
                q2_head += 1
                return f, idx

        for _ in range(n - 1):
            f1, i1 = _pick_min()
            f2, i2 = _pick_min()
            parent[i1] = node_count
            parent[i2] = node_count
            q2.append((f1 + f2, node_count))
            node_count += 1

        depth = [0] * node_count
        for nd in range(node_count - 2, -1, -1):
            depth[nd] = depth[parent[nd]] + 1

        for i, sym in enumerate(symbols):
            lengths[sym] = min(depth[i], LZMS_MAX_CODEWORD_LENGTH)

        return lengths

    def decode(self) -> int:
        if self._syms_until_rebuild == 0:
            self._build()

        self._syms_until_rebuild -= 1

        if self._decode_table is None:
            sym = 0
        else:
            sym = self._read_symbol()

        self._freqs[sym] += 1

        if self._syms_until_rebuild == 0:
            for i in range(self._num_syms):
                self._freqs[i] = (self._freqs[i] >> 1) + 1

        return sym

    def _read_symbol(self) -> int:
        bs = self._bitstream
        tb = self._table_bits
        table = self._decode_table
        assert table

        bs.ensure(LZMS_MAX_CODEWORD_LENGTH)
        idx = bs.peek(tb)
        entry = table[idx]
        symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT
        length = entry & DECODE_TABLE_LENGTH_MASK

        if entry >= (1 << (tb + DECODE_TABLE_SYMBOL_SHIFT)):
            bs.remove(tb)
            entry = table[symbol + bs.peek(length)]
            symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT
            length = entry & DECODE_TABLE_LENGTH_MASK

        bs.remove(length)
        return symbol


def lzms_x86_filter(data: bytearray, size: int):
    if size <= 17:
        return

    _IS_OPCODE = bytearray(256)
    _IS_OPCODE[0x48] = 1
    _IS_OPCODE[0x4C] = 1
    _IS_OPCODE[0xE8] = 1
    _IS_OPCODE[0xE9] = 1
    _IS_OPCODE[0xF0] = 1
    _IS_OPCODE[0xFF] = 1

    last_x86_pos = -LZMS_X86_MAX_TRANSLATION_OFF - 1
    last_target_usages = [-LZMS_X86_ID_WINDOW_SIZE - 1] * 65536

    tail = size - 16
    i = 1

    while i < tail:
        if not _IS_OPCODE[data[i]]:
            i += 1
            continue

        opcode = data[i]
        max_trans_off = LZMS_X86_MAX_TRANSLATION_OFF
        opcode_nbytes = 0

        if opcode >= 0xF0:
            if opcode & 0x0F:
                if i + 1 < size and data[i + 1] == 0x15:
                    opcode_nbytes = 2
            else:
                if i + 2 < size and data[i + 1] == 0x83 and data[i + 2] == 0x05:
                    opcode_nbytes = 3
        elif opcode <= 0x4C:
            if i + 2 < size and (data[i + 2] & 0x07) == 0x05:
                if data[i + 1] == 0x8D or (
                    data[i + 1] == 0x8B and not (data[i] & 0x04) and not (data[i + 2] & 0xF0)
                ):
                    opcode_nbytes = 3
        else:
            if opcode & 0x01:
                i += 5
                continue
            else:
                opcode_nbytes = 1
                max_trans_off >>= 1

        if opcode_nbytes == 0:
            i += 1
            continue

        pos = i
        i += opcode_nbytes

        if i + 4 > size:
            break

        target16 = pos + int.from_bytes(data[i:i + 2], 'little')
        target16 &= 0xFFFF

        if pos - last_x86_pos <= max_trans_off:
            n = int.from_bytes(data[i:i + 4], 'little')
            n = (n - pos) & 0xFFFFFFFF
            data[i:i + 4] = n.to_bytes(4, 'little')

        check_pos = pos + opcode_nbytes + 3

        if check_pos - last_target_usages[target16] <= LZMS_X86_ID_WINDOW_SIZE:
            last_x86_pos = check_pos

        last_target_usages[target16] = check_pos
        i += 4


def lzms_decompress(src_data: buf, target: int) -> bytes:
    if not src_data or len(src_data) < 4 or (len(src_data) & 1):
        return B''

    num_offset_slots = _lzms_get_num_offset_slots(target)

    rd = LzmsRangeDecoder(src_data)
    bs = LzmsInputBitStream(src_data)

    literal_dec = LzmsHuffmanDecoder(bs, LZMS_NUM_LITERAL_SYMS, LZMS_LITERAL_REBUILD_FREQ, LZMS_LITERAL_TABLEBITS)
    lz_offset_dec = LzmsHuffmanDecoder(bs, num_offset_slots, LZMS_LZ_OFFSET_REBUILD_FREQ, LZMS_LZ_OFFSET_TABLEBITS)
    length_dec = LzmsHuffmanDecoder(bs, LZMS_NUM_LENGTH_SYMS, LZMS_LENGTH_REBUILD_FREQ, LZMS_LENGTH_TABLEBITS)
    delta_power_dec = LzmsHuffmanDecoder(bs, LZMS_NUM_DELTA_POWER_SYMS, LZMS_DELTA_POWER_REBUILD_FREQ, LZMS_DELTA_POWER_TABLEBITS)
    delta_offset_dec = LzmsHuffmanDecoder(bs, num_offset_slots, LZMS_DELTA_OFFSET_REBUILD_FREQ, LZMS_DELTA_OFFSET_TABLEBITS)

    main_probs = [LzmsProbEntry() for _ in range(LZMS_NUM_MAIN_PROBS)]
    match_probs = [LzmsProbEntry() for _ in range(LZMS_NUM_MATCH_PROBS)]
    lz_probs = [LzmsProbEntry() for _ in range(LZMS_NUM_LZ_PROBS)]
    delta_probs = [LzmsProbEntry() for _ in range(LZMS_NUM_DELTA_PROBS)]
    lz_rep_probs = [[LzmsProbEntry() for _ in range(LZMS_NUM_LZ_REP_PROBS)] for _ in range(LZMS_NUM_LZ_REPS - 1)]
    delta_rep_probs = [[LzmsProbEntry() for _ in range(LZMS_NUM_DELTA_REP_PROBS)] for _ in range(LZMS_NUM_DELTA_REPS - 1)]

    main_state = [0]
    match_state = [0]
    lz_state = [0]
    delta_state = [0]
    lz_rep_states = [[0], [0]]
    delta_rep_states = [[0], [0]]

    recent_lz_offsets = [1, 2, 3, 4]
    recent_delta_pairs = [1, 2, 3, 4]

    prev_item_type = 0

    output = bytearray()

    def _decode_lz_offset() -> int:
        slot = lz_offset_dec.decode()
        return LZMS_OFFSET_SLOT_BASE[slot] + bs.read(LZMS_EXTRA_OFFSET_BITS[slot])

    def _decode_length() -> int:
        slot = length_dec.decode()
        return LZMS_LENGTH_SLOT_BASE[slot] + bs.read(LZMS_EXTRA_LENGTH_BITS[slot])

    def _decode_delta_offset() -> int:
        slot = delta_offset_dec.decode()
        return LZMS_OFFSET_SLOT_BASE[slot] + bs.read(LZMS_EXTRA_OFFSET_BITS[slot])

    while len(output) < target:
        if not rd.decode_bit(main_state, LZMS_NUM_MAIN_PROBS, main_probs):
            output.append(literal_dec.decode())
            prev_item_type = 0

        elif not rd.decode_bit(match_state, LZMS_NUM_MATCH_PROBS, match_probs):
            if not rd.decode_bit(lz_state, LZMS_NUM_LZ_PROBS, lz_probs):
                offset = _decode_lz_offset()
                recent_lz_offsets[3] = recent_lz_offsets[2]
                recent_lz_offsets[2] = recent_lz_offsets[1]
                recent_lz_offsets[1] = recent_lz_offsets[0]
            else:
                adj = prev_item_type & 1
                if not rd.decode_bit(lz_rep_states[0], LZMS_NUM_LZ_REP_PROBS, lz_rep_probs[0]):
                    offset = recent_lz_offsets[0 + adj]
                    recent_lz_offsets[0 + adj] = recent_lz_offsets[0]
                elif not rd.decode_bit(lz_rep_states[1], LZMS_NUM_LZ_REP_PROBS, lz_rep_probs[1]):
                    offset = recent_lz_offsets[1 + adj]
                    recent_lz_offsets[1 + adj] = recent_lz_offsets[1]
                    recent_lz_offsets[1] = recent_lz_offsets[0]
                else:
                    offset = recent_lz_offsets[2 + adj]
                    recent_lz_offsets[2 + adj] = recent_lz_offsets[2]
                    recent_lz_offsets[2] = recent_lz_offsets[1]
                    recent_lz_offsets[1] = recent_lz_offsets[0]

            recent_lz_offsets[0] = offset
            prev_item_type = 1

            length = _decode_length()
            pos = len(output)
            if offset > pos:
                raise RuntimeError(F'LZMS: LZ offset {offset} exceeds position {pos}')
            for k in range(length):
                output.append(output[pos - offset + k])

        else:
            adj = prev_item_type >> 1
            if not rd.decode_bit(delta_state, LZMS_NUM_DELTA_PROBS, delta_probs):
                power = delta_power_dec.decode()
                raw_offset = _decode_delta_offset()
                pair = (power << 32) | raw_offset
                recent_delta_pairs[3] = recent_delta_pairs[2]
                recent_delta_pairs[2] = recent_delta_pairs[1]
                recent_delta_pairs[1] = recent_delta_pairs[0]
            else:
                if not rd.decode_bit(delta_rep_states[0], LZMS_NUM_DELTA_REP_PROBS, delta_rep_probs[0]):
                    pair = recent_delta_pairs[0 + adj]
                    recent_delta_pairs[0 + adj] = recent_delta_pairs[0]
                elif not rd.decode_bit(delta_rep_states[1], LZMS_NUM_DELTA_REP_PROBS, delta_rep_probs[1]):
                    pair = recent_delta_pairs[1 + adj]
                    recent_delta_pairs[1 + adj] = recent_delta_pairs[1]
                    recent_delta_pairs[1] = recent_delta_pairs[0]
                else:
                    pair = recent_delta_pairs[2 + adj]
                    recent_delta_pairs[2 + adj] = recent_delta_pairs[2]
                    recent_delta_pairs[2] = recent_delta_pairs[1]
                    recent_delta_pairs[1] = recent_delta_pairs[0]

                power = pair >> 32
                raw_offset = pair & 0xFFFFFFFF

            recent_delta_pairs[0] = pair
            prev_item_type = 2

            length = _decode_length()
            span = 1 << power
            offset = raw_offset << power

            pos = len(output)
            if offset + span > pos:
                raise RuntimeError('LZMS: delta offset+span exceeds position')
            for k in range(length):
                output.append(
                    (output[pos + k - offset] + output[pos + k - span] - output[pos + k - span - offset]) & 0xFF
                )

    if len(output) > target:
        output = output[:target]

    lzms_x86_filter(output, target)
    return bytes(output)
