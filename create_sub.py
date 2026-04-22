import re
class Generate_Sub:
    def __init__(self, pk1, pk2, file):
        self.pk1 = pk1
        self.pk2 = pk2
        self.file = file

    def _calc_raw(self):
        var1 = self.pk1.replace(' ', '')
        var2 = self.pk2.replace(' ', '')
        bin_val1 = bin(int(var1, 16))[2:]
        bin_val2 = bin(int(var2, 16))[2:]
        prelude = '0000000000000000'
        manchester1 = prelude + bin_val1
        manchester2 = prelude + bin_val2
        temp1 = ''
        temp2 = ''
        raw1 = ''
        raw2 = ''
        for i in range(len(manchester1) - 1):
            if manchester1[i] == '1':
                temp1 += '0'
            else:
                temp1 += '1'
            temp1 += manchester1[i]

            if manchester2[i] == '1':
                temp2 += '0'
            else:
                temp2 += '1'
            temp2 += manchester1[i]


        return temp1, temp2

    def _gen_sub(self, bits):
        res = ''
        pause = 250

        data = []
        prevbit = None
        prevbitlen = 0
        for bit in bits:
            if prevbit and prevbit != bit:
                data.append(prevbitlen)
                prevbitlen = 0

            if bit == '1':
                prevbitlen += 250
            else:
                prevbitlen -= 250

            prevbit = bit

        if prevbit == '1':
            data.append(prevbitlen)
            data.append(-pause)
        else:
            data.append(prevbitlen - pause)

        datalines = []
        for i in range(0, len(data), 512):
            batch = [str(n) for n in data[i:i+512]]
            datalines.append(f'RAW_Data: {" ".join(batch)}')
        res += '\n'.join(datalines)

        return res
        

    def create_file(self):
        raw1, raw2 = self._calc_raw()
        open(self.file, 'x')

        with open(self.file, 'w') as f:
            f.write('Filetype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 315000000\nPreset: FuriHalSubGhzPresetOok650Async\nProtocol: RAW\n')
            f.write('RAW_Data: ' + self._gen_sub(raw1) + '\n')
            f.write('RAW_Data: ' + self._gen_sub(raw2))
        
