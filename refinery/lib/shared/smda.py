from refinery.lib.shared import dependency


@dependency('smda<2.0', ['all'])
def smda():
    import datetime
    datetime.UTC = datetime.timezone.utc
    import smda
    import smda.Disassembler
    import smda.DisassemblyResult
    return smda
