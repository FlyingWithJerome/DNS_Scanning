from bitarray import bitarray
from numpy    import log
from xxhash   import xxh32_intdigest

class IntegerBloomFilter(object):
    '''
    A bloom filter that can memorize a lot of integers
    Not thread safe
    '''
    def __init__(self, expected_number_appended=15*10**8):
        expected_fp = 1 / expected_number_appended
        bit_length  = expected_number_appended / log(0.6185) / log(expected_fp)
        bit_length  = int(bit_length) + 1

        self.__bit_array = bitarray(bit_length)
        self.__length    = bit_length
        self.__num_hash  = -log(expected_fp) / log(2)
        self.__num_hash  = int(self.__num_hash) + 1

    def __contains__(self, number:int):
        for anchor in self.__get_anchors(number):
            if not self.__bit_array[anchor]:
                return False

        return True

    def __len__(self):
        return self.__length

    def append(self, number:int):
        for anchor in self.__get_anchors(number):
            self.__bit_array[anchor] = 1

    def __get_anchors(self, number:int):
        number_str = str(number)
        anchors    = []
        for seed in range(self.__num_hash):
            anchor = xxh32_intdigest(number_str, seed=seed)
            anchors.append(anchor % self.__length)

        return anchors

if __name__ == "__main__":
    i = IntegerBloomFilter()
    i.append(254524524)
    i.append(140000000)
    i.append(141411143)

    import time

    start = time.time()
    254524524 in i
    end = time.time()
    print("time elapsed:", end - start)

    print("filter size:", len(i))

    print(254524524 in i)
    print(141411143 in i)
    print(1 in i)
    print(17 in i)

